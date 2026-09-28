#include "session/client_session.h"

#include "platform/integrity.h"
#include "transport/tcp_transport.h"
#include "transport/transport_factory.h"

#include "sockgate_common/protocol/enrollment_token.h"
#include "sockgate_common/protocol/messages.h"
#include "sockgate_common/protocol/transcript.h"
#include "sockgate_common/tls/tls.h"

#include <algorithm>
#include <cstring>

namespace sg::client {
namespace {

constexpr size_t kReadChunk = 16 * 1024;
constexpr size_t kMaxQueuedBytes = 64u * 1024 * 1024;
// Best-effort budget for the polite CLOSE / close_notify on Disconnect: it
// must never make Disconnect block on a peer that stopped reading.
constexpr uint32_t kPoliteCloseTimeoutMs = 200;

uint32_t ClampToU32(uint64_t v) { return v > 0xFFFFFFFFu ? 0xFFFFFFFFu : static_cast<uint32_t>(v); }

void CopyString(char* dst, size_t cap, const std::string& src)
{
    if (cap == 0) return;
    const size_t n = std::min(cap - 1, src.size());
    std::memcpy(dst, src.data(), n);
    dst[n] = '\0';
}

}  // namespace

ClientSession::ClientSession(ClientSettings settings) : settings_(std::move(settings))
{
    limits_.max_data_payload = settings_.max_payload;
}

ClientSession::~ClientSession()
{
    Disconnect();
    SecureZero(channel_binding_.data(), channel_binding_.size());
    SecureZero(last_transcript_.data(), last_transcript_.size());
}

// ---- identity -------------------------------------------------------------------------

Status ClientSession::EnsureIdentity(IdentityInfo* out)
{
    IdentityInfo local;
    IdentityInfo* info = out != nullptr ? out : &local;
    SG_TRY(sg::client::EnsureIdentity(*settings_.key_store, settings_.identity_name, info));
    if (info->created) {
        SG_LOGI(settings_.logger, "event=identity_created installation=%s keystore=%s",
                ShortId(info->installation_id).c_str(), KeyStoreKindName(info->kind));
    }
    return OkStatus();
}

Status ClientSession::GetIdentity(IdentityInfo* out)
{
    return sg::client::GetIdentity(*settings_.key_store, settings_.identity_name, out);
}

Status ClientSession::DeleteIdentity(bool force)
{
    std::lock_guard<std::mutex> control(control_mutex_);
    const uint32_t s = state_.load();
    if (s != SG_CLIENT_STATE_DISCONNECTED && s != SG_CLIENT_STATE_CLOSED && s != SG_CLIENT_STATE_EXPIRED) {
        return SG_INVALID_STATE;
    }
    return force ? settings_.key_store->ForceDeleteKey(settings_.identity_name)
                 : settings_.key_store->DeleteKey(settings_.identity_name);
}

// ---- generations ----------------------------------------------------------------------

ClientSession::Link ClientSession::CurrentLink()
{
    std::lock_guard<std::mutex> lock(link_mutex_);
    return link_;
}

bool ClientSession::IsCurrent(uint64_t generation)
{
    std::lock_guard<std::mutex> lock(link_mutex_);
    return link_.generation == generation && link_.tls != nullptr;
}

bool ClientSession::SetStateIfCurrent(uint64_t generation, uint32_t state)
{
    std::lock_guard<std::mutex> lock(link_mutex_);
    if (link_.generation != generation || link_.tls == nullptr) return false;
    state_.store(state);
    return true;
}

Status ClientSession::Fail(uint64_t generation, Status status, uint32_t new_state)
{
    std::shared_ptr<TlsChannel> tls;
    {
        std::lock_guard<std::mutex> lock(link_mutex_);
        // Stale (a newer connection exists) or already torn down: leave the state alone.
        if (link_.generation != generation || !link_.tls) return status;
        tls = std::move(link_.tls);
        link_.channel.reset();
        state_.store(new_state);
    }
    if (tls) tls->Abort();
    return status;
}

// ---- helpers ------------------------------------------------------------------------------

Status ClientSession::ValidateTarget(const ServerTarget& t) const
{
    if (t.host.empty() || t.host.size() > 253 || t.port == 0) return SG_INVALID_ARGUMENT;
    if (t.ca_file.empty() && t.ca_pem.empty() && !t.trust_system_store) return SG_INVALID_ARGUMENT;
    if (t.spki_pins.size() > SG_MAX_PINS || t.proof_keys.size() > SG_MAX_PROOF_KEYS) return SG_INVALID_ARGUMENT;
    // Trusting the OS store without pins or proof keys lets any user-installed
    // CA impersonate the server; this must be an explicit decision.
    if (t.trust_system_store && t.spki_pins.empty() && t.proof_keys.empty() && !t.allow_no_pinning) {
        return SG_INVALID_ARGUMENT;
    }
    for (const auto& key : t.proof_keys) SG_TRY(crypto::ValidateP256PublicKey(key));
    return OkStatus();
}

void ClientSession::ResetReceiveStateLocked(uint64_t generation)
{
    decoder_ = std::make_unique<proto::FrameDecoder>([this](const proto::FrameHeader& h) {
        return proto::CheckHeaderForState(h, proto::Role::kClient, phase_, limits_);
    });
    decoder_->SetMaxBuffered(proto::kPreAuthDecoderBuffer);
    phase_ = proto::Phase::kClosed;
    queue_.clear();
    queued_bytes_ = 0;
    reauth_waiting_ = false;
    reauth_arrived_ = false;
    recv_generation_ = generation;
}

Status ClientSession::CheckUsable(const Link& link)
{
    const uint32_t s = state_.load();
    if (s == SG_CLIENT_STATE_EXPIRED) return SG_SESSION_EXPIRED;
    if (s == SG_CLIENT_STATE_CLOSED) return SG_CLOSED;
    if (s != SG_CLIENT_STATE_ACTIVE && s != SG_CLIENT_STATE_REFRESHING) return SG_INVALID_STATE;
    if (!link.tls || !link.channel) return SG_CLOSED;
    uint64_t expires;
    {
        std::lock_guard<std::mutex> lock(info_mutex_);
        expires = expires_at_;
    }
    if (expires != 0 && MonotonicMs() >= expires) {
        SG_LOGI(settings_.logger, "event=session_expired state=local");
        return Fail(link.generation, SG_SESSION_EXPIRED, SG_CLIENT_STATE_EXPIRED);
    }
    return OkStatus();
}

Status ClientSession::MaybeAutoRefresh()
{
    if ((settings_.flags & SG_CLIENT_FLAG_AUTO_REFRESH) == 0 || state_.load() != SG_CLIENT_STATE_ACTIVE) {
        return OkStatus();
    }
    bool due;
    {
        std::lock_guard<std::mutex> lock(info_mutex_);
        due = lifetime_ms_ != 0 && MonotonicMs() >= authenticated_at_ + lifetime_ms_ * 8 / 10;
    }
    return due ? RefreshImpl(true) : OkStatus();
}

Status ClientSession::OpenTransport(const ServerTarget& target, uint64_t attempt,
                                    std::shared_ptr<net::ITransport>* out)
{
    TransportRequest request;
    request.host = target.host;
    request.port = target.port;
    request.connect_timeout_ms = settings_.connect_timeout_ms;
    request.io_timeout_ms = settings_.io_timeout_ms;
    request.proxy = &settings_.proxy;
    request.logger = &settings_.logger;
    return CreateConnectedTransport(request, out, [this, attempt](const std::shared_ptr<net::ITransport>& t) {
        std::lock_guard<std::mutex> lock(link_mutex_);
        if (link_.generation != attempt) {
            t->Shutdown();  // Disconnect() already ran (e.g. during a proxy lookup): stop at once
            return;
        }
        connecting_transport_ = t;
    });
}

// ---- connect / authenticate ---------------------------------------------------------------

Status ClientSession::Connect(const ServerTarget& target)
{
    std::lock_guard<std::mutex> control(control_mutex_);
    const uint32_t s = state_.load();
    if (s != SG_CLIENT_STATE_DISCONNECTED && s != SG_CLIENT_STATE_CLOSED && s != SG_CLIENT_STATE_EXPIRED) {
        return SG_INVALID_STATE;
    }
    // A Disconnect() from another thread from here on changes link_.generation:
    // this attempt then ends with SG_CLOSED (checked before and after each step).
    uint64_t attempt;
    bool aborted = false;
    {
        std::lock_guard<std::mutex> lock(link_mutex_);
        attempt = link_.generation;
    }
    SG_TRY(ValidateTarget(target));

    tls::TlsClientConfig tls_config;
    tls_config.server_name = target.server_name.empty() ? target.host : target.server_name;
    tls_config.ca_file = target.ca_file;
    tls_config.ca_pem = target.ca_pem;
    tls_config.trust_system_store = target.trust_system_store;
    tls_config.spki_pins = target.spki_pins;
    tls_config.allow_tls12 = (settings_.flags & SG_CLIENT_FLAG_ALLOW_TLS12) != 0;
    std::shared_ptr<tls::ITlsContext> context;
    SG_TRY(tls::DefaultTlsProvider().CreateClientContext(tls_config, &context));

    // Once per process, to the first client that logs warnings at all.
    static std::atomic<bool> openssl_checked{false};
    if (settings_.logger.Enabled(SG_LOG_WARN) && !openssl_checked.exchange(true)) {
        if (const char* outdated = tls::OutdatedBundledOpenSslVersion()) {
            SG_LOGW(settings_.logger,
                    "event=config_warning detail=\"bundled %s predates OpenSSL 3.0.7: rebuild with a current "
                    "OpenSSL\"",
                    outdated);
        }
    }

    {
        std::lock_guard<std::mutex> lock(link_mutex_);
        aborted = link_.generation != attempt;  // Disconnect() during validation / trust setup
        if (!aborted) state_.store(SG_CLIENT_STATE_CONNECTING);
    }
    if (aborted) {
        SG_LOGI(settings_.logger, "event=connect_aborted host=%s", target.host.c_str());
        return SG_CLOSED;
    }
    // One budget for resolution, TCP, the proxy and the TLS handshake together.
    const Deadline connect_deadline(settings_.connect_timeout_ms);
    std::shared_ptr<net::ITransport> transport;
    const Status connected = OpenTransport(target, attempt, &transport);
    {
        std::lock_guard<std::mutex> lock(link_mutex_);
        connecting_transport_.reset();
        aborted = link_.generation != attempt;
    }
    if (aborted) {
        if (transport) transport->Close();
        SG_LOGI(settings_.logger, "event=connect_aborted host=%s", target.host.c_str());
        return SG_CLOSED;
    }
    if (!connected.ok()) {
        SG_LOGW(settings_.logger, "event=connect_failed host=%s port=%u err=%s", target.host.c_str(),
                static_cast<unsigned>(target.port), connected.name());
        state_.store(SG_CLIENT_STATE_CLOSED);
        return connected;
    }

    if (connect_deadline.Expired()) {
        // TCP / the proxy used the whole budget: not a TLS failure.
        SG_LOGW(settings_.logger, "event=connect_failed host=%s port=%u err=SG_TIMEOUT", target.host.c_str(),
                static_cast<unsigned>(target.port));
        transport->Close();
        state_.store(SG_CLIENT_STATE_CLOSED);
        return SG_TIMEOUT;
    }

    std::unique_ptr<tls::ITlsEngine> engine;
    Status st = context->CreateEngine(&engine);
    if (!st.ok()) {
        transport->Close();
        state_.store(SG_CLIENT_STATE_CLOSED);
        return st;
    }
    auto channel = std::make_shared<TlsChannel>(std::move(transport), std::move(engine));
    uint64_t generation = 0;
    {
        // Published before the handshake so Disconnect() can abort it.
        std::lock_guard<std::mutex> lock(link_mutex_);
        aborted = link_.generation != attempt;
        if (!aborted) {
            generation = next_generation_++;
            link_.tls = channel;
            link_.channel.reset();
            link_.generation = generation;
            state_.store(SG_CLIENT_STATE_TLS_HANDSHAKE);
        }
    }
    if (aborted) {
        channel->Abort();
        SG_LOGI(settings_.logger, "event=connect_aborted host=%s", target.host.c_str());
        return SG_CLOSED;
    }
    // What the transport left of the budget (Handshake(0) would mean "no limit").
    st = channel->Handshake(connect_deadline.infinite() ? 0u
                                                        : std::max<uint32_t>(1, connect_deadline.RemainingMs(UINT32_MAX)));
    if (!st.ok()) {
        {
            std::lock_guard<std::mutex> lock(link_mutex_);
            aborted = link_.generation != generation;
        }
        // Disconnect() tore the handshake down: not a TLS failure. Certificate
        // and pinning failures are still reported as such.
        if (aborted && st != SG_PINNING_ERROR && st != SG_CERTIFICATE_ERROR) {
            SG_LOGI(settings_.logger, "event=connect_aborted host=%s", target.host.c_str());
            return SG_CLOSED;
        }
        SG_LOGW(settings_.logger, "event=tls_failed host=%s err=%s detail=\"%s\"", target.host.c_str(), st.name(),
                channel->ErrorDetail().c_str());
        if (st == SG_PINNING_ERROR) {
            // The chain validated against a trusted CA but not the pinned keys.
            SG_LOGE(settings_.logger, "event=possible_tls_interception host=%s", target.host.c_str());
        }
        return Fail(generation, st);
    }

    {
        std::lock_guard<std::mutex> recv(recv_mutex_);
        ResetReceiveStateLocked(generation);
        target_ = target;
    }
    {
        std::lock_guard<std::mutex> lock(info_mutex_);
        session_id_ = proto::SessionId{};
        epoch_ = 0;
        policy_ = SG_SESSION_POLICY_NONE;
        granted_features_ = 0;
        license_expires_at_ms_ = 0;
        expires_at_ = 0;
        lifetime_ms_ = 0;
    }
    const tls::TlsSessionInfo info = channel->SessionInfo();
    SG_LOGI(settings_.logger, "event=tls_established peer=%s protocol=%s cipher=%s", channel->PeerAddress().c_str(),
            info.protocol.c_str(), info.cipher.c_str());
    // A concurrent Disconnect() wins: never resurrect a torn-down connection.
    if (!SetStateIfCurrent(generation, SG_CLIENT_STATE_TLS_ESTABLISHED)) {
        SG_LOGI(settings_.logger, "event=connect_aborted host=%s", target.host.c_str());
        return SG_CLOSED;
    }
    return OkStatus();
}

Status ClientSession::Authenticate(const std::string* enrollment_token)
{
    std::lock_guard<std::mutex> control(control_mutex_);
    if (state_.load() != SG_CLIENT_STATE_TLS_ESTABLISHED) return SG_INVALID_STATE;

    IdentityInfo identity;
    if ((settings_.flags & SG_CLIENT_FLAG_AUTO_IDENTITY) != 0 || enrollment_token != nullptr) {
        SG_TRY(EnsureIdentity(&identity));
    } else {
        const Status st = GetIdentity(&identity);
        if (st == SG_NOT_FOUND) {
            SG_LOGW(settings_.logger, "event=auth_failed err=identity_missing name=%s", settings_.identity_name.c_str());
        }
        SG_TRY(st);
    }

    EnrollmentMaterial enrollment;
    struct WipeKey {
        crypto::Sha256Digest& key;
        ~WipeKey() { SecureZero(key.data(), key.size()); }
    } wipe_k_tok{enrollment.k_tok};  // K_tok is secret: wiped on every return path
    if (enrollment_token != nullptr) {
        SG_TRY(proto::ParseEnrollmentToken(*enrollment_token, &enrollment.token_pub, &enrollment.k_tok));
    }

    const Link link = CurrentLink();
    if (!link.tls) return SG_CLOSED;
    const uint64_t gen = link.generation;
    TlsChannel& tls = *link.tls;

    std::lock_guard<std::mutex> recv(recv_mutex_);
    if (recv_generation_ != gen) return SG_CLOSED;
    if (!SetStateIfCurrent(gen, SG_CLIENT_STATE_AUTHENTICATING)) return SG_CLOSED;
    const Deadline deadline(settings_.io_timeout_ms);

    crypto::Sha256Digest cb;
    Status st = tls.ChannelBinding(&cb);
    if (!st.ok()) return Fail(gen, st);

    ClientHandshakeConfig hs_config = settings_.handshake;
    hs_config.server_proof_keys = target_.proof_keys;
    if ((settings_.flags & SG_CLIENT_FLAG_INTEGRITY_REPORT) != 0) {
        // Fresh observations for every authentication (file hashes are cached).
        st = os::CollectIntegrityReport(&hs_config.integrity);
        if (!st.ok()) return Fail(gen, st);
        hs_config.has_integrity = true;
    }
    ClientHandshake handshake(hs_config, *settings_.key_store, settings_.identity_name);

    Bytes out;
    st = handshake.Start(cb, enrollment_token != nullptr ? &enrollment : nullptr, &out);
    SecureZero(enrollment.k_tok.data(), enrollment.k_tok.size());
    if (!st.ok()) return Fail(gen, st);
    {
        std::lock_guard<std::mutex> send(send_mutex_);
        st = tls.Send(out.data(), out.size());
    }
    if (!st.ok()) return Fail(gen, st);

    phase_ = proto::Phase::kAwaitServerHello;
    proto::DecodedFrame frame;
    st = ReadFrameLocked(tls, &frame, deadline);
    if (!st.ok()) return Fail(gen, st);

    ClientHandshakeResult result;
    if (frame.header().type == proto::MessageType::kAuthResult) {
        st = handshake.OnAuthResult(frame, &result);  // version negotiation failure
        return Fail(gen, st.ok() ? Status(SG_PROTOCOL_ERROR) : st);
    }
    out.clear();
    st = handshake.OnServerHello(frame, &out);
    if (!st.ok()) return Fail(gen, st);
    {
        std::lock_guard<std::mutex> send(send_mutex_);
        st = tls.Send(out.data(), out.size());
    }
    if (!st.ok()) return Fail(gen, st);

    phase_ = proto::Phase::kAwaitAuthResult;
    st = ReadFrameLocked(tls, &frame, deadline);
    if (!st.ok()) return Fail(gen, st);
    st = handshake.OnAuthResult(frame, &result);
    if (!st.ok()) {
        SG_LOGW(settings_.logger, "event=auth_failed installation=%s err=%s", ShortId(identity.installation_id).c_str(),
                st.name());
        return Fail(gen, st);
    }

    // Session keys from the TLS exporter bound to the transcript.
    SecureBytes km(32);
    st = tls.ExportKeyingMaterial(proto::kKeyExporterLabel, result.transcript_hash, km.data(), km.size());
    auto channel = std::make_shared<proto::ProtectedChannel>(proto::Role::kClient);
    if (st.ok()) st = channel->Initialize(km, result.session_id);
    if (!st.ok()) return Fail(gen, st);

    const uint64_t now = MonotonicMs();
    {
        std::lock_guard<std::mutex> lock(info_mutex_);
        session_id_ = result.session_id;
        channel_binding_ = cb;
        last_transcript_ = result.transcript_hash;
        epoch_ = 0;
        policy_ = static_cast<uint32_t>(result.auth_result.policy);
        granted_features_ = result.auth_result.granted_features;
        license_expires_at_ms_ = result.auth_result.license_expires_at_ms;
        authenticated_at_ = now;
        lifetime_ms_ = result.auth_result.session_lifetime_ms;
        expires_at_ = now + lifetime_ms_;
    }
    phase_ = proto::Phase::kActive;
    decoder_->SetMaxBuffered(proto::kHeaderSize + settings_.max_payload + proto::kAuthTagSize + 64 * 1024);
    {
        std::lock_guard<std::mutex> send(send_mutex_);
        std::lock_guard<std::mutex> lock(link_mutex_);
        if (link_.generation != gen || !link_.tls) return SG_CLOSED;  // disconnected meanwhile
        link_.channel = std::move(channel);
        state_.store(SG_CLIENT_STATE_AUTHENTICATED);
    }
    SG_LOGI(settings_.logger, "event=authenticated session=%s installation=%s policy=%u features=%llu lifetime_ms=%u",
            ShortId(result.session_id).c_str(), ShortId(identity.installation_id).c_str(),
            static_cast<unsigned>(result.auth_result.policy),
            static_cast<unsigned long long>(result.auth_result.granted_features),
            result.auth_result.session_lifetime_ms);
    return SetStateIfCurrent(gen, SG_CLIENT_STATE_ACTIVE) ? OkStatus() : Status(SG_CLOSED);
}

// ---- frame I/O ------------------------------------------------------------------------------

Status ClientSession::ReadFrameLocked(TlsChannel& tls, proto::DecodedFrame* out, const Deadline& deadline)
{
    uint8_t buffer[kReadChunk];
    for (;;) {
        bool ready = false;
        SG_TRY(decoder_->Next(out, &ready));
        if (ready) {
            // The header was validated when it arrived; the phase may have
            // changed since (e.g. Refresh started), so check it again.
            return proto::CheckHeaderForState(out->header(), proto::Role::kClient, phase_, limits_);
        }
        if (deadline.Expired()) return SG_TIMEOUT;
        const uint32_t wait = deadline.infinite() ? net::kNoTimeout : std::max<uint32_t>(1, deadline.RemainingMs(UINT32_MAX));
        size_t n = 0;
        SG_TRY(tls.Receive(buffer, sizeof(buffer), &n, wait));
        const Status st = decoder_->Append(ByteView(buffer, n));
        SecureZero(buffer, n);
        SG_TRY(st);
    }
}

Status ClientSession::SendFrame(const Link& link, proto::MessageType type, ByteView payload,
                                const proto::SealOptions& options, Bytes* frame_out)
{
    std::lock_guard<std::mutex> send(send_mutex_);
    if (!link.channel || !link.tls) return SG_INVALID_STATE;
    Bytes frame;
    SG_TRY(link.channel->Seal(type, payload, options, &frame));
    SG_TRY(link.tls->Send(frame.data(), frame.size()));
    if (frame_out != nullptr) *frame_out = std::move(frame);
    return OkStatus();
}

Status ClientSession::HandleSessionFrameLocked(const Link& link, proto::DecodedFrame& frame)
{
    const proto::MessageType type = frame.header().type;
    const bool is_reauth = type == proto::MessageType::kReauthChallenge || type == proto::MessageType::kReauthResult;
    Bytes plaintext;
    const Status opened = link.channel->Open(&frame, is_reauth ? &plaintext : nullptr);
    if (!opened.ok()) {
        SG_LOGW(settings_.logger, "event=frame_rejected type=%s seq=%llu err=%s", proto::MessageTypeName(type),
                static_cast<unsigned long long>(frame.header().sequence), opened.name());
        return opened;
    }

    switch (type) {
    case proto::MessageType::kData: {
        const size_t size = frame.payload().size();
        if (queued_bytes_ + size > kMaxQueuedBytes) return SG_LIMIT_EXCEEDED;
        QueuedMessage msg;
        msg.data.assign(frame.payload().begin(), frame.payload().end());
        msg.request_id = frame.header().request_id;
        msg.flags = ((frame.header().flags & proto::kFlagEncrypted) ? SG_MESSAGE_FLAG_ENCRYPTED : 0u) |
                    ((frame.header().flags & proto::kFlagResponse) ? SG_MESSAGE_FLAG_RESPONSE : 0u);
        queued_bytes_ += size;
        queue_.push_back(std::move(msg));
        return OkStatus();
    }
    case proto::MessageType::kPing: {
        proto::PingPong ping;
        SG_TRY(proto::DecodePingPong(frame.payload(), &ping));
        Bytes payload;
        SG_TRY(proto::EncodePingPong(ping, &payload));
        return SendFrame(link, proto::MessageType::kPong, payload, proto::SealOptions());
    }
    case proto::MessageType::kPong: {
        proto::PingPong pong;
        return proto::DecodePingPong(frame.payload(), &pong);
    }
    case proto::MessageType::kClose: {
        proto::CloseMessage close;
        SG_TRY(proto::DecodeClose(frame.payload(), &close));
        SG_LOGI(settings_.logger, "event=closed_by_server reason=%u", static_cast<unsigned>(close.reason));
        if (close.reason == proto::CloseReason::kSessionExpired) return SG_SESSION_EXPIRED;
        return close.reason == proto::CloseReason::kAuthFailed ? Status(SG_SERVER_REJECTED) : Status(SG_CLOSED);
    }
    case proto::MessageType::kReauthChallenge:
    case proto::MessageType::kReauthResult:
        // Only the frame the refresh logic is waiting for is acceptable.
        if (!reauth_waiting_ || reauth_arrived_ || type != reauth_expected_) return SG_PROTOCOL_ERROR;
        reauth_frame_ = std::move(frame);
        reauth_plaintext_ = std::move(plaintext);
        reauth_arrived_ = true;
        return OkStatus();
    default:
        return SG_PROTOCOL_ERROR;  // excluded by the header rules; defensive
    }
}

Status ClientSession::DeliverLocked(uint8_t* buffer, size_t capacity, size_t* received, SG_MessageInfo* info)
{
    QueuedMessage& front = queue_.front();
    if (front.data.size() > capacity) {
        *received = front.data.size();
        return SG_BUFFER_TOO_SMALL;
    }
    if (!front.data.empty()) std::memcpy(buffer, front.data.data(), front.data.size());
    *received = front.data.size();
    if (info != nullptr) {
        info->request_id = front.request_id;
        info->flags = front.flags;
    }
    queued_bytes_ -= front.data.size();
    queue_.pop_front();
    return OkStatus();
}

// ---- data API -----------------------------------------------------------------------------

Status ClientSession::Send(ByteView data, uint64_t reply_to_request_id, uint64_t* out_request_id)
{
    if (data.size() > settings_.max_payload) return SG_INVALID_ARGUMENT;
    SG_TRY(MaybeAutoRefresh());
    const Link link = CurrentLink();
    SG_TRY(CheckUsable(link));

    proto::SealOptions options;
    options.encrypt = (settings_.flags & SG_CLIENT_FLAG_APP_ENCRYPTION) != 0;
    if (reply_to_request_id != 0) {
        options.request_id = reply_to_request_id;
        options.response = true;
    }
    Status st;
    {
        std::lock_guard<std::mutex> send(send_mutex_);
        if (!options.response) options.request_id = link.channel->NextRequestId();
        Bytes frame;
        st = link.channel->Seal(proto::MessageType::kData, data, options, &frame);
        if (st == SG_INVALID_ARGUMENT) return st;  // e.g. reply to a request we never received
        if (st.ok()) st = link.tls->Send(frame.data(), frame.size());
    }
    // A failed or partial TLS write leaves this connection unusable.
    if (!st.ok()) return Fail(link.generation, st);
    if (out_request_id != nullptr) *out_request_id = options.response ? 0 : options.request_id;
    return OkStatus();
}

Status ClientSession::Receive(uint8_t* buffer, size_t capacity, size_t* received, SG_MessageInfo* info,
                              uint32_t timeout_ms)
{
    if (received == nullptr || (buffer == nullptr && capacity != 0)) return SG_INVALID_ARGUMENT;
    *received = 0;
    SG_TRY(MaybeAutoRefresh());
    const Link link = CurrentLink();

    std::lock_guard<std::mutex> recv(recv_mutex_);
    if (!queue_.empty() && recv_generation_ == link.generation) return DeliverLocked(buffer, capacity, received, info);
    SG_TRY(CheckUsable(link));
    if (recv_generation_ != link.generation) return SG_CLOSED;  // reconnected while we waited

    const Deadline deadline(timeout_ms);
    for (;;) {
        proto::DecodedFrame frame;
        Status st = ReadFrameLocked(*link.tls, &frame, deadline);
        if (st == SG_TIMEOUT) return st;  // not fatal
        if (st.ok()) st = HandleSessionFrameLocked(link, frame);
        if (!st.ok()) {
            return Fail(link.generation, st,
                        st == SG_SESSION_EXPIRED ? SG_CLIENT_STATE_EXPIRED : SG_CLIENT_STATE_CLOSED);
        }
        if (!queue_.empty()) return DeliverLocked(buffer, capacity, received, info);
    }
}

Status ClientSession::Ping()
{
    const Link link = CurrentLink();
    SG_TRY(CheckUsable(link));
    proto::PingPong ping;
    ping.opaque = MonotonicMs();
    Bytes payload;
    SG_TRY(proto::EncodePingPong(ping, &payload));
    const Status st = SendFrame(link, proto::MessageType::kPing, payload, proto::SealOptions());
    return st.ok() ? st : Fail(link.generation, st);
}

// ---- reauthentication -------------------------------------------------------------------

Status ClientSession::WaitForReauthFrameLocked(const Link& link, proto::MessageType type, const Deadline& deadline,
                                               proto::DecodedFrame* out, Bytes* plaintext_frame)
{
    reauth_expected_ = type;
    reauth_waiting_ = true;
    reauth_arrived_ = false;
    while (!reauth_arrived_) {
        proto::DecodedFrame frame;
        Status st = ReadFrameLocked(*link.tls, &frame, deadline);
        if (st.ok()) st = HandleSessionFrameLocked(link, frame);
        if (!st.ok()) {
            reauth_waiting_ = false;
            return st;
        }
    }
    reauth_waiting_ = false;
    *out = std::move(reauth_frame_);
    *plaintext_frame = std::move(reauth_plaintext_);
    return OkStatus();
}

Status ClientSession::Refresh() { return RefreshImpl(false); }

Status ClientSession::RefreshImpl(bool opportunistic)
{
    std::lock_guard<std::mutex> control(control_mutex_);
    if (opportunistic) {
        // Re-check under the control lock: another thread may just have refreshed.
        std::lock_guard<std::mutex> lock(info_mutex_);
        if (lifetime_ms_ == 0 || MonotonicMs() < authenticated_at_ + lifetime_ms_ * 8 / 10) return OkStatus();
    }
    if (state_.load() != SG_CLIENT_STATE_ACTIVE) {
        if (opportunistic) return OkStatus();
        return state_.load() == SG_CLIENT_STATE_EXPIRED ? Status(SG_SESSION_EXPIRED) : Status(SG_INVALID_STATE);
    }
    const Link link = CurrentLink();
    SG_TRY(CheckUsable(link));

    // The reauth exchange must own the receive side. An automatic refresh
    // never waits for a Receive() blocked in another thread (it would wait
    // for data that may never come); it simply tries again on a later call.
    std::unique_lock<std::mutex> recv(recv_mutex_, std::defer_lock);
    if (opportunistic) {
        if (!recv.try_lock()) return OkStatus();
    } else {
        recv.lock();
    }
    if (recv_generation_ != link.generation) return SG_CLOSED;

    const uint64_t gen = link.generation;
    if (!SetStateIfCurrent(gen, SG_CLIENT_STATE_REFRESHING)) return SG_CLOSED;
    phase_ = proto::Phase::kRefreshing;
    const Deadline deadline(settings_.io_timeout_ms);

    proto::SessionId sid;
    crypto::Sha256Digest cb;
    crypto::Sha256Digest prev_th;
    uint32_t epoch;
    {
        std::lock_guard<std::mutex> lock(info_mutex_);
        sid = session_id_;
        cb = channel_binding_;
        prev_th = last_transcript_;
        epoch = epoch_;
    }

    auto fail = [&](Status st) {
        phase_ = proto::Phase::kClosed;
        SG_LOGW(settings_.logger, "event=refresh_failed session=%s err=%s", ShortId(sid).c_str(), st.name());
        return Fail(gen, st, st == SG_SESSION_EXPIRED ? SG_CLIENT_STATE_EXPIRED : SG_CLIENT_STATE_CLOSED);
    };

    // REAUTH_REQUEST (reauth frames are never application-encrypted, so the
    // plaintext view F(x) is simply the wire frame without its tag).
    proto::ReauthRequest request;
    Status st = crypto::RandomArray(&request.client_nonce);
    Bytes payload;
    if (st.ok()) st = proto::EncodeReauthRequest(request, &payload);
    Bytes request_frame;
    if (st.ok()) st = SendFrame(link, proto::MessageType::kReauthRequest, payload, proto::SealOptions(), &request_frame);
    if (!st.ok()) return fail(st);
    request_frame.resize(request_frame.size() - proto::kAuthTagSize);

    proto::DecodedFrame challenge_frame;
    Bytes challenge_plain;
    st = WaitForReauthFrameLocked(link, proto::MessageType::kReauthChallenge, deadline, &challenge_frame, &challenge_plain);
    if (!st.ok()) return fail(st);
    proto::ReauthChallenge challenge;
    st = proto::DecodeReauthChallenge(challenge_frame.payload(), &challenge);
    if (!st.ok()) return fail(st);

    crypto::Sha256Digest thr;
    st = proto::ComputeReauthTranscriptHash(sid, epoch, cb, prev_th, request_frame, challenge_plain, &thr);
    proto::ReauthProof proof;
    if (st.ok()) {
        st = settings_.key_store->Sign(settings_.identity_name, proto::SignedData(proto::kReauthProofContext, thr),
                                       &proof.signature);
    }
    payload.clear();
    if (st.ok()) st = proto::EncodeReauthProof(proof, &payload);
    if (st.ok()) st = SendFrame(link, proto::MessageType::kReauthProof, payload, proto::SealOptions());
    if (!st.ok()) return fail(st);

    proto::DecodedFrame result_frame;
    Bytes result_plain;
    st = WaitForReauthFrameLocked(link, proto::MessageType::kReauthResult, deadline, &result_frame, &result_plain);
    if (!st.ok()) return fail(st);
    proto::ReauthResult result;
    st = proto::DecodeReauthResult(result_frame.payload(), &result);
    if (!st.ok()) return fail(st);
    if (result.result != proto::AuthResultCode::kOk) return fail(SG_SERVER_REJECTED);
    if (result.new_epoch != epoch + 1) return fail(SG_PROTOCOL_ERROR);

    // The server switched s2c right after REAUTH_RESULT: switch receive now,
    // and send under the send lock so no frame is sealed with a mixed epoch.
    SecureBytes km(32);
    st = link.tls->ExportKeyingMaterial(proto::kKeyExporterLabel, thr, km.data(), km.size());
    if (st.ok()) st = link.channel->SwitchReceiveKey(km, result.new_epoch);
    if (st.ok()) {
        std::lock_guard<std::mutex> send(send_mutex_);
        st = link.channel->SwitchSendKey(km, result.new_epoch);
        if (st.ok()) st = link.tls->RequestKeyUpdate();  // also rotate the TLS traffic keys
    }
    if (!st.ok()) return fail(st);

    const uint64_t now = MonotonicMs();
    {
        std::lock_guard<std::mutex> lock(info_mutex_);
        last_transcript_ = thr;
        epoch_ = result.new_epoch;
        authenticated_at_ = now;
        lifetime_ms_ = result.session_lifetime_ms;
        expires_at_ = now + lifetime_ms_;
    }
    phase_ = proto::Phase::kActive;
    SG_LOGI(settings_.logger, "event=refreshed session=%s epoch=%u lifetime_ms=%u", ShortId(sid).c_str(),
            result.new_epoch, result.session_lifetime_ms);
    return SetStateIfCurrent(gen, SG_CLIENT_STATE_ACTIVE) ? OkStatus() : Status(SG_CLOSED);
}

// ---- teardown / info --------------------------------------------------------------------

void ClientSession::Disconnect() noexcept
{
    try {
        Link link;
        std::shared_ptr<net::ITransport> connecting;
        uint32_t previous;
        {
            std::lock_guard<std::mutex> lock(link_mutex_);
            link = std::move(link_);
            link_ = Link();
            link_.generation = next_generation_++;  // anything still running is now stale
            connecting = std::move(connecting_transport_);
            previous = state_.load();
            if (previous != SG_CLIENT_STATE_DISCONNECTED && previous != SG_CLIENT_STATE_EXPIRED) {
                state_.store(SG_CLIENT_STATE_CLOSED);
            }
        }
        if (connecting) connecting->Shutdown();  // aborts a connect in progress

        if (link.tls && link.channel &&
            (previous == SG_CLIENT_STATE_ACTIVE || previous == SG_CLIENT_STATE_REFRESHING)) {
            // Polite CLOSE, best effort: skipped if another thread is mid-send,
            // and bounded so a peer that stopped reading cannot block us.
            std::unique_lock<std::mutex> send(send_mutex_, std::try_to_lock);
            if (send.owns_lock()) {
                proto::CloseMessage close;
                Bytes payload;
                Bytes frame;
                if (proto::EncodeClose(close, &payload).ok() &&
                    link.channel->Seal(proto::MessageType::kClose, payload, proto::SealOptions(), &frame).ok()) {
                    link.tls->SendFor(frame.data(), frame.size(), kPoliteCloseTimeoutMs).IgnoreError();
                }
            }
        }
        if (link.tls) link.tls->Shutdown(kPoliteCloseTimeoutMs);  // close_notify + transport shutdown

        if (previous != SG_CLIENT_STATE_DISCONNECTED) SG_LOGI(settings_.logger, "event=disconnected");

        // Wait for operations that were woken up to leave, then drop the
        // receive state of the old connection (or an older one) - unless a
        // Connect() on another thread already set up a newer one meanwhile
        // (generations only grow).
        std::lock_guard<std::mutex> recv(recv_mutex_);
        std::lock_guard<std::mutex> send(send_mutex_);
        if (recv_generation_ <= link.generation) {
            queue_.clear();
            queued_bytes_ = 0;
            phase_ = proto::Phase::kClosed;
            recv_generation_ = 0;
        }
    } catch (...) {
        // Allocation failure while disconnecting: the transport shutdown above
        // (if reached) already woke every blocked operation.
    }
}

Status ClientSession::GetSessionInfo(SG_ClientSessionInfo* info)
{
    if (info == nullptr) return SG_INVALID_ARGUMENT;
    info->state = state_.load();
    {
        std::lock_guard<std::mutex> lock(info_mutex_);
        info->policy = policy_;
        std::memcpy(info->session_id.bytes, session_id_.data(), session_id_.size());
        info->granted_features = granted_features_;
        info->license_expires_at_ms = license_expires_at_ms_;
        const uint64_t now = MonotonicMs();
        info->expires_in_ms = expires_at_ > now ? ClampToU32(expires_at_ - now) : 0;
        info->epoch = epoch_;
    }
    info->tls_protocol[0] = '\0';
    info->tls_cipher[0] = '\0';
    const Link link = CurrentLink();
    if (link.tls) {
        const tls::TlsSessionInfo t = link.tls->SessionInfo();
        CopyString(info->tls_protocol, sizeof(info->tls_protocol), t.protocol);
        CopyString(info->tls_cipher, sizeof(info->tls_cipher), t.cipher);
    }
    return OkStatus();
}

}  // namespace sg::client
