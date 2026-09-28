#include "session/connection.h"

#include "sockgate_common/core/clock.h"
#include "sockgate_common/protocol/messages.h"
#include "sockgate_common/protocol/transcript.h"

#include <algorithm>

namespace sg::server {
namespace {

constexpr size_t kPlainChunk = 16 * 1024;
constexpr size_t kMaxPendingEventBytes = 64u * 1024 * 1024;  // hard cap per connection
constexpr size_t kReadPauseBytes = 8u * 1024 * 1024;        // backpressure watermark
constexpr size_t kMaxPendingWriteBytes = 32u * 1024 * 1024;

}  // namespace

Connection::Connection(ServerEngine* engine, std::shared_ptr<AsyncStream> stream, std::unique_ptr<tls::ITlsEngine> tls,
                       SG_SessionHandle handle, uint64_t now_ms)
    : engine_(engine),
      stream_(std::move(stream)),
      handle_(handle),
      tls_(std::move(tls)),
      decoder_([this](const proto::FrameHeader& h) {
          return proto::CheckHeaderForState(h, proto::Role::kServer, phase_, limits_);
      }),
      handshake_(engine->auth_context()),
      accepted_at_(now_ms)
{
    limits_.max_data_payload = engine_->config().max_payload;
    decoder_.SetMaxBuffered(proto::kPreAuthDecoderBuffer);
    handshake_.set_session_handle(handle_);
}

Connection::~Connection()
{
    SecureZero(channel_binding_.data(), channel_binding_.size());
    SecureZero(last_transcript_.data(), last_transcript_.size());
    SecureZero(reauth_challenge_.data(), reauth_challenge_.size());
}

void Connection::Start() { IssueRead(); }

void Connection::IssueRead()
{
    auto self = shared_from_this();
    const Status st = stream_->AsyncRead(
        [self](Status status, const uint8_t* data, size_t size) { self->OnRead(status, data, size); });
    if (!st.ok()) {
        {
            std::lock_guard<std::mutex> lock(mutex_);
            CloseLocked(proto::CloseReason::kNormal, SG_CLOSED, false, false);
        }
        DeliverEvents();
    }
}

void Connection::OnRead(Status status, const uint8_t* data, size_t size)
{
    bool keep_reading = false;
    {
        Lock lock(mutex_);
        if (closed_) {
            // Already closing: remaining input is discarded (the I/O service drains it).
        } else if (!status.ok()) {
            CloseLocked(proto::CloseReason::kNormal, status == SG_CLOSED ? Status(SG_CLOSED) : Status(SG_NETWORK_ERROR),
                        false, false);
        } else {
            const Status st = ProcessLocked(lock, ByteView(data, size));
            if (!st.ok() && !closed_) {
                if (st != SG_CLOSED) {
                    engine_->mutable_stats().protocol_errors.fetch_add(1);
                    SG_LOGW(engine_->logger(), "event=connection_error session=%s peer=%s phase=%s err=%s",
                            ShortId(outcome_.session_id).c_str(), stream_->PeerAddress().c_str(),
                            proto::PhaseName(phase_), st.name());
                }
                const bool authenticated = phase_ == proto::Phase::kActive || phase_ == proto::Phase::kRefreshing;
                CloseLocked(st == SG_CLOSED ? proto::CloseReason::kNormal : proto::CloseReason::kProtocolError,
                            st, authenticated && st != SG_CLOSED, true);
            }
            // A peer that keeps sending (e.g. PINGs, KeyUpdates) while never
            // reading makes our replies pile up: cut it off instead of
            // buffering without bound.
            if (!closed_ && stream_->PendingWriteBytes() > kMaxPendingWriteBytes) {
                SG_LOGW(engine_->logger(), "event=connection_error session=%s peer=%s err=SG_LIMIT_EXCEEDED detail=unread_output",
                        ShortId(outcome_.session_id).c_str(), stream_->PeerAddress().c_str());
                CloseLocked(proto::CloseReason::kLimitExceeded, SG_LIMIT_EXCEEDED, false, false);
            }
            if (!closed_ && pending_event_bytes_ + delivering_bytes_ > kReadPauseBytes) {
                read_paused_ = true;  // resumed by DeliverEvents() once the application caught up
            }
            keep_reading = !closed_ && !read_paused_;
        }
    }
    DeliverEvents();
    if (keep_reading) IssueRead();
}

// ---- inbound processing (mutex_ held) ------------------------------------------------

Status Connection::ProcessLocked(Lock& lock, ByteView ciphertext)
{
    SG_TRY(tls_->FeedIncoming(ciphertext));
    if (!tls_ready_) {
        const Status hs = tls_->Handshake();
        FlushLocked();
        if (hs == kStatusWouldBlock) return OkStatus();
        if (!hs.ok()) {
            SG_LOGI(engine_->logger(), "event=tls_failed peer=%s err=%s detail=\"%s\"", stream_->PeerAddress().c_str(),
                    hs.name(), tls_->ErrorDetail().c_str());
            return hs;
        }
        SG_TRY(tls_->ChannelBinding(&channel_binding_));
        tls_ready_ = true;
    }

    uint8_t plain[kPlainChunk];
    for (;;) {
        size_t n = 0;
        const Status rst = tls_->Read(plain, sizeof(plain), &n);
        if (rst == kStatusWouldBlock) break;
        if (!rst.ok()) return rst;  // SG_CLOSED on close_notify
        const Status ast = decoder_.Append(ByteView(plain, n));
        SecureZero(plain, n);
        SG_TRY(ast);
        for (;;) {
            proto::DecodedFrame frame;
            bool ready = false;
            SG_TRY(decoder_.Next(&frame, &ready));
            if (!ready) break;
            // Re-validate against the *current* phase (it may have changed
            // since the header was first checked).
            SG_TRY(proto::CheckHeaderForState(frame.header(), proto::Role::kServer, phase_, limits_));
            SG_TRY(HandleFrameLocked(lock, frame));
            if (closed_) return OkStatus();
        }
    }
    FlushLocked();  // e.g. KeyUpdate responses generated while reading
    return OkStatus();
}

Status Connection::HandleFrameLocked(Lock& lock, proto::DecodedFrame& frame)
{
    switch (phase_) {
    case proto::Phase::kAwaitClientHello:
        return HandleClientHelloLocked(frame);
    case proto::Phase::kAwaitClientProof:
        return HandleClientProofLocked(lock, frame);
    case proto::Phase::kActive:
    case proto::Phase::kRefreshing:
        return HandleSessionFrameLocked(lock, frame);
    default:
        return SG_PROTOCOL_ERROR;
    }
}

Status Connection::HandleClientHelloLocked(const proto::DecodedFrame& frame)
{
    if (frame.header().type == proto::MessageType::kClose) {
        CloseLocked(proto::CloseReason::kNormal, SG_CLOSED, false, true);
        return OkStatus();
    }
    Bytes reply;
    const Status st = handshake_.OnClientHello(frame, channel_binding_, stream_->PeerAddress(), &reply);
    if (st.ok()) {
        SG_TRY(WriteRawLocked(reply));
        phase_ = proto::Phase::kAwaitClientProof;
        return OkStatus();
    }
    if (st == SG_VERSION_MISMATCH) {
        WriteRawLocked(reply).IgnoreError();
        SG_LOGI(engine_->logger(), "event=auth_rejected peer=%s reason=\"%s\"", stream_->PeerAddress().c_str(),
                handshake_.failure_reason().c_str());
        CloseLocked(proto::CloseReason::kProtocolError, SG_VERSION_MISMATCH, false, true);
        return OkStatus();
    }
    return st;
}

Status Connection::HandleClientProofLocked(Lock& lock, const proto::DecodedFrame& frame)
{
    if (frame.header().type == proto::MessageType::kClose) {
        CloseLocked(proto::CloseReason::kNormal, SG_CLOSED, false, true);
        return OkStatus();
    }
    Bytes reply;
    HandshakeOutcome outcome;
    const uint64_t revocations = engine_->revocation_generation();
    // The handshake calls application code (on_authorize / on_enroll), which
    // may call back into the server API for this very session: never hold
    // mutex_ across it. Only this read-processing thread touches handshake_.
    lock.unlock();
    Status st = handshake_.OnClientProof(frame, &reply, &outcome);
    lock.lock();
    if (closed_) return OkStatus();  // closed meanwhile (timeout, CloseSession, Stop)
    // Revocation passes only see open sessions; one that raced with this
    // authorisation is caught here (the session opens under this lock).
    if (st.ok() && engine_->revocation_generation() != revocations &&
        !engine_->IsStillAuthorized(outcome.installation_id, outcome.decision)) {
        // A revocation that ran before the seat was taken could not free it.
        engine_->ReleaseNewSeat(outcome.installation_id, outcome.decision);
        st = handshake_.Reject("revoked during authentication", &reply);
    }
    if (st == SG_AUTH_FAILED) {
        WriteRawLocked(reply).IgnoreError();
        engine_->mutable_stats().auth_failed.fetch_add(1);
        // The precise reason stays in the server log; the client saw a generic rejection.
        SG_LOGW(engine_->logger(), "event=auth_rejected peer=%s installation=%s reason=\"%s\"",
                stream_->PeerAddress().c_str(), ShortId(handshake_.claimed_installation_id()).c_str(),
                handshake_.failure_reason().c_str());
        CloseLocked(proto::CloseReason::kAuthFailed, SG_AUTH_FAILED, false, true);
        return OkStatus();
    }
    SG_TRY(st);
    SG_TRY(WriteRawLocked(reply));

    SecureBytes km(32);
    SG_TRY(tls_->ExportKeyingMaterial(proto::kKeyExporterLabel, outcome.transcript_hash, true, km.data(), km.size()));
    auto channel = std::make_unique<proto::ProtectedChannel>(proto::Role::kServer);
    SG_TRY(channel->Initialize(km, outcome.session_id));
    channel_ = std::move(channel);

    const uint64_t now = MonotonicMs();
    outcome_ = std::move(outcome);
    last_transcript_ = outcome_.transcript_hash;
    epoch_ = 0;
    expires_at_ = now + outcome_.session_lifetime_ms;
    last_activity_ = now;
    last_reauth_at_ = now;
    phase_ = proto::Phase::kActive;
    decoder_.SetMaxBuffered(proto::kHeaderSize + engine_->config().max_payload + proto::kAuthTagSize + 64 * 1024);
    opened_ = true;
    counted_active_ = true;
    LeaveUnauthenticated();
    engine_->mutable_stats().auth_succeeded.fetch_add(1);
    engine_->mutable_stats().active_sessions.fetch_add(1);

    SG_LOGI(engine_->logger(),
            "event=session_opened session=%s installation=%s peer=%s policy=%u features=%llu lifetime_ms=%u enrolled=%d",
            ShortId(outcome_.session_id).c_str(), ShortId(outcome_.installation_id).c_str(),
            stream_->PeerAddress().c_str(), static_cast<unsigned>(outcome_.decision.policy),
            static_cast<unsigned long long>(outcome_.decision.granted_features), outcome_.session_lifetime_ms,
            outcome_.enrolled ? 1 : 0);

    Event opened;
    opened.kind = Event::Kind::kOpened;
    SnapshotLocked(&opened.snapshot, now);
    pending_events_.push_back(std::move(opened));
    return OkStatus();
}

Status Connection::HandleSessionFrameLocked(Lock& lock, proto::DecodedFrame& frame)
{
    const proto::MessageType type = frame.header().type;
    const bool reauth = type == proto::MessageType::kReauthRequest || type == proto::MessageType::kReauthProof;
    Bytes plaintext;
    const Status opened = channel_->Open(&frame, reauth ? &plaintext : nullptr);
    if (!opened.ok()) {
        SG_LOGW(engine_->logger(), "event=frame_rejected session=%s type=%s seq=%llu err=%s",
                ShortId(outcome_.session_id).c_str(), proto::MessageTypeName(type),
                static_cast<unsigned long long>(frame.header().sequence), opened.name());
        return opened;
    }
    last_activity_ = MonotonicMs();

    switch (type) {
    case proto::MessageType::kData: {
        const bool encrypted = (frame.header().flags & proto::kFlagEncrypted) != 0;
        if (engine_->config().require_app_encryption && !encrypted) return SG_PROTOCOL_ERROR;
        peer_encrypts_ = peer_encrypts_ || encrypted;
        const size_t size = frame.payload().size();
        if (pending_event_bytes_ + size > kMaxPendingEventBytes) return SG_LIMIT_EXCEEDED;
        Event msg;
        msg.kind = Event::Kind::kMessage;
        msg.data.assign(frame.payload().begin(), frame.payload().end());
        msg.request_id = frame.header().request_id;
        msg.flags = (encrypted ? SG_MESSAGE_FLAG_ENCRYPTED : 0u) |
                    ((frame.header().flags & proto::kFlagResponse) ? SG_MESSAGE_FLAG_RESPONSE : 0u);
        pending_event_bytes_ += size;
        pending_events_.push_back(std::move(msg));
        engine_->mutable_stats().messages_received.fetch_add(1);
        return OkStatus();
    }
    case proto::MessageType::kPing: {
        proto::PingPong ping;
        SG_TRY(proto::DecodePingPong(frame.payload(), &ping));
        Bytes payload;
        SG_TRY(proto::EncodePingPong(ping, &payload));
        return SealAndWriteLocked(proto::MessageType::kPong, payload, proto::SealOptions());
    }
    case proto::MessageType::kPong: {
        proto::PingPong pong;
        return proto::DecodePingPong(frame.payload(), &pong);
    }
    case proto::MessageType::kClose: {
        proto::CloseMessage close;
        SG_TRY(proto::DecodeClose(frame.payload(), &close));
        CloseLocked(proto::CloseReason::kNormal, SG_CLOSED, false, true);
        return OkStatus();
    }
    case proto::MessageType::kReauthRequest:
        return HandleReauthRequestLocked(frame, plaintext);
    case proto::MessageType::kReauthProof:
        return HandleReauthProofLocked(lock, frame);
    default:
        return SG_PROTOCOL_ERROR;
    }
}

// ---- reauthentication ----------------------------------------------------------------

Status Connection::HandleReauthRequestLocked(const proto::DecodedFrame& frame, const Bytes& plaintext)
{
    const uint64_t now = MonotonicMs();
    // One switch at a time, and a per-session rate limit on signature checks.
    if (channel_->HasStagedReceiveKey()) return SG_PROTOCOL_ERROR;
    if (ElapsedMs(now, last_reauth_at_) < engine_->config().min_reauth_interval_ms) return SG_PROTOCOL_ERROR;

    proto::ReauthRequest request;
    SG_TRY(proto::DecodeReauthRequest(frame.payload(), &request));

    proto::ReauthChallenge challenge;
    SG_TRY(crypto::RandomArray(&challenge.server_nonce));
    SG_TRY(crypto::RandomArray(&challenge.challenge));
    challenge.challenge_ttl_ms = engine_->auth_context()->config.challenge_ttl_ms;
    Bytes payload;
    SG_TRY(proto::EncodeReauthChallenge(challenge, &payload));
    Bytes sealed;
    SG_TRY(SealAndWriteLocked(proto::MessageType::kReauthChallenge, payload, proto::SealOptions(), &sealed));

    // F(x) = header || plaintext payload (reauth frames are never encrypted).
    reauth_request_f_ = plaintext;
    reauth_challenge_f_.assign(sealed.begin(), sealed.end() - static_cast<std::ptrdiff_t>(proto::kAuthTagSize));
    reauth_challenge_ = challenge.challenge;
    reauth_issued_at_ = now;
    last_reauth_at_ = now;
    phase_ = proto::Phase::kRefreshing;
    return OkStatus();
}

Status Connection::RejectReauthLocked(const std::string& reason)
{
    proto::ReauthResult result;
    result.result = proto::AuthResultCode::kRejected;
    Bytes payload;
    if (proto::EncodeReauthResult(result, &payload).ok()) {
        SealAndWriteLocked(proto::MessageType::kReauthResult, payload, proto::SealOptions()).IgnoreError();
    }
    engine_->mutable_stats().auth_failed.fetch_add(1);
    SG_LOGW(engine_->logger(), "event=reauth_rejected session=%s installation=%s reason=\"%s\"",
            ShortId(outcome_.session_id).c_str(), ShortId(outcome_.installation_id).c_str(), reason.c_str());
    CloseLocked(proto::CloseReason::kAuthFailed, SG_AUTH_FAILED, false, true);
    return OkStatus();
}

Status Connection::HandleReauthProofLocked(Lock& lock, const proto::DecodedFrame& frame)
{
    proto::ReauthProof proof;
    SG_TRY(proto::DecodeReauthProof(frame.payload(), &proof));
    const auto ctx = engine_->auth_context();
    const uint64_t now = MonotonicMs();
    const bool fresh = ElapsedMs(now, reauth_issued_at_) <= ctx->config.challenge_ttl_ms;
    SecureZero(reauth_challenge_.data(), reauth_challenge_.size());  // single use

    crypto::Sha256Digest thr;
    SG_TRY(proto::ComputeReauthTranscriptHash(outcome_.session_id, epoch_, channel_binding_, last_transcript_,
                                              reauth_request_f_, reauth_challenge_f_, &thr));

    ClientRecord record;
    const Status found = engine_->registry().Find(outcome_.installation_id, &record);
    const bool usable = found.ok() && record.status == ClientStatus::kActive;
    const crypto::P256PublicKey& key = usable ? record.public_key : ctx->dummy_key;
    const bool signature_ok =
        crypto::VerifyP256(key, proto::SignedData(proto::kReauthProofContext, thr), proof.signature).ok();
    if (!usable) return RejectReauthLocked("installation no longer active");
    if (!signature_ok) return RejectReauthLocked("invalid signature");
    if (!fresh) return RejectReauthLocked("challenge expired");

    // Authorisation is re-evaluated: revoked licenses or changed policies apply now.
    AuthorizationRequest request;
    request.installation_id = outcome_.installation_id;
    request.record = &record;
    request.mode = outcome_.hello.auth_mode;
    request.reauthentication = true;
    request.session_handle = handle_;
    request.product_id = outcome_.hello.product_id;
    request.product_version = outcome_.hello.product_version;
    request.license_id = outcome_.hello.license_id;
    request.has_requested_features = outcome_.hello.has_requested_features;
    request.requested_features = outcome_.hello.requested_features;
    request.client_version_major = outcome_.hello.client_version_major;
    request.client_version_minor = outcome_.hello.client_version_minor;
    request.client_version_patch = outcome_.hello.client_version_patch;
    request.has_integrity = outcome_.hello.has_integrity;
    request.integrity = outcome_.hello.integrity;
    request.peer_address = stream_->PeerAddress();
    AuthorizationDecision decision;
    // Application callback: run without mutex_ (see HandleClientProofLocked).
    lock.unlock();
    const Status authz = engine_->authorizer().Authorize(request, &decision);
    lock.lock();
    if (closed_ || phase_ != proto::Phase::kRefreshing) return OkStatus();
    if (!authz.ok() || !decision.allow) return RejectReauthLocked("authorization denied: " + decision.deny_reason);
    bool expired = false;
    const uint32_t lifetime = ComputeLifetimeLocked(decision, &expired);
    if (expired) return RejectReauthLocked("license expired");

    proto::ReauthResult result;
    result.result = proto::AuthResultCode::kOk;
    result.session_lifetime_ms = lifetime;
    result.new_epoch = epoch_ + 1;
    Bytes payload;
    SG_TRY(proto::EncodeReauthResult(result, &payload));
    // Protected with the current (old) epoch key; then switch our send key
    // immediately and stage the new receive key (04 §7.3).
    SG_TRY(SealAndWriteLocked(proto::MessageType::kReauthResult, payload, proto::SealOptions()));

    SecureBytes km(32);
    SG_TRY(tls_->ExportKeyingMaterial(proto::kKeyExporterLabel, thr, true, km.data(), km.size()));
    SG_TRY(channel_->SwitchSendKey(km, result.new_epoch));
    SG_TRY(channel_->StageReceiveKey(km, result.new_epoch));
    SG_TRY(tls_->RequestKeyUpdate());
    FlushLocked();

    epoch_ = result.new_epoch;
    last_transcript_ = thr;
    expires_at_ = now + lifetime;
    outcome_.decision = decision;
    outcome_.session_lifetime_ms = lifetime;
    phase_ = proto::Phase::kActive;
    SG_LOGI(engine_->logger(), "event=session_refreshed session=%s epoch=%u lifetime_ms=%u",
            ShortId(outcome_.session_id).c_str(), epoch_, lifetime);
    return OkStatus();
}

uint32_t Connection::ComputeLifetimeLocked(const AuthorizationDecision& decision, bool* expired) const
{
    const HandshakeConfig& cfg = engine_->auth_context()->config;
    uint64_t lifetime = decision.session_lifetime_ms != 0 ? decision.session_lifetime_ms : cfg.default_session_lifetime_ms;
    lifetime = std::min<uint64_t>(lifetime, cfg.max_session_lifetime_ms);
    *expired = false;
    if (decision.license_expires_at_ms != 0) {
        const uint64_t now = engine_->auth_context()->UnixNow();
        if (decision.license_expires_at_ms <= now) {
            *expired = true;
            return 0;
        }
        lifetime = std::min<uint64_t>(lifetime, decision.license_expires_at_ms - now);
    }
    return static_cast<uint32_t>(std::max<uint64_t>(lifetime, 1));
}

// ---- outbound ------------------------------------------------------------------------

void Connection::FlushLocked()
{
    if (tls_->PendingOutgoing() == 0) return;
    Bytes out;
    tls_->TakeOutgoing(&out);
    if (!out.empty()) stream_->AsyncWrite(std::move(out), nullptr).IgnoreError();
}

Status Connection::WriteRawLocked(ByteView frame)
{
    SG_TRY(tls_->Write(frame));
    FlushLocked();
    return OkStatus();
}

Status Connection::SealAndWriteLocked(proto::MessageType type, ByteView payload, const proto::SealOptions& options,
                                      Bytes* sealed_out)
{
    if (!channel_) return SG_INVALID_STATE;
    Bytes frame;
    SG_TRY(channel_->Seal(type, payload, options, &frame));
    SG_TRY(WriteRawLocked(frame));
    if (sealed_out != nullptr) *sealed_out = std::move(frame);
    return OkStatus();
}

Status Connection::Send(ByteView data, uint64_t reply_to_request_id)
{
    {
        std::lock_guard<std::mutex> lock(mutex_);
        if (closed_ || !channel_) return SG_CLOSED;
        if (phase_ != proto::Phase::kActive && phase_ != proto::Phase::kRefreshing) return SG_INVALID_STATE;
        if (data.size() > engine_->config().max_payload) return SG_INVALID_ARGUMENT;
        if (stream_->PendingWriteBytes() > kMaxPendingWriteBytes) return SG_LIMIT_EXCEEDED;  // slow reader

        proto::SealOptions options;
        options.encrypt = engine_->config().require_app_encryption || peer_encrypts_;
        if (reply_to_request_id != 0) {
            options.request_id = reply_to_request_id;
            options.response = true;
        } else {
            options.request_id = channel_->NextRequestId();
        }
        const Status st = SealAndWriteLocked(proto::MessageType::kData, data, options);
        if (st.ok()) {
            engine_->mutable_stats().messages_sent.fetch_add(1);
            return st;
        }
        if (st == SG_INVALID_ARGUMENT) return st;  // e.g. reply to an unknown request id
        CloseLocked(proto::CloseReason::kProtocolError, st, false, false);
    }
    DeliverEvents();
    return SG_CLOSED;
}

// ---- lifecycle ----------------------------------------------------------------------

void Connection::CloseLocked(proto::CloseReason reason, Status status, bool notify_peer, bool graceful)
{
    if (closed_) return;
    const bool authenticated = phase_ == proto::Phase::kActive || phase_ == proto::Phase::kRefreshing;
    if (notify_peer && authenticated && channel_) {
        proto::CloseMessage close;
        close.reason = reason;
        Bytes payload;
        if (proto::EncodeClose(close, &payload).ok()) {
            SealAndWriteLocked(proto::MessageType::kClose, payload, proto::SealOptions()).IgnoreError();
        }
    }
    closed_ = true;
    closing_since_ = MonotonicMs();
    phase_ = proto::Phase::kClosed;
    if (tls_ready_) {
        tls_->Shutdown().IgnoreError();  // close_notify
        FlushLocked();
    }
    channel_.reset();  // destroys the session keys
    if (graceful) {
        stream_->CloseAfterWrites();
    } else {
        stream_->Close();
    }

    if (counted_active_) {
        counted_active_ = false;
        engine_->mutable_stats().active_sessions.fetch_sub(1);
    }
    if (opened_) {
        SG_LOGI(engine_->logger(), "event=session_closed session=%s installation=%s reason=%u status=%s",
                ShortId(outcome_.session_id).c_str(), ShortId(outcome_.installation_id).c_str(),
                static_cast<unsigned>(reason), status.name());
        Event closed;
        closed.kind = Event::Kind::kClosed;
        closed.reason = ToPublicStatus(status);
        pending_events_.push_back(std::move(closed));
    }
    Event remove;
    remove.kind = Event::Kind::kRemove;
    pending_events_.push_back(std::move(remove));
}

void Connection::Close(proto::CloseReason reason, Status status)
{
    {
        std::lock_guard<std::mutex> lock(mutex_);
        CloseLocked(reason, status, true, true);
    }
    DeliverEvents();
}

void Connection::ForceClose() noexcept { stream_->Close(); }

void Connection::Tick()
{
    {
        std::lock_guard<std::mutex> lock(mutex_);
        if (closed_) return;
        // Read the clock under the lock: I/O threads update the timestamps
        // below concurrently, and a stale `now` would wrap the subtraction.
        const uint64_t now = MonotonicMs();
        const EngineConfig& cfg = engine_->config();
        const bool authenticated = phase_ == proto::Phase::kActive || phase_ == proto::Phase::kRefreshing;
        if (!authenticated) {
            if (ElapsedMs(now, accepted_at_) > cfg.handshake_timeout_ms) {
                SG_LOGI(engine_->logger(), "event=handshake_timeout peer=%s phase=%s", stream_->PeerAddress().c_str(),
                        proto::PhaseName(phase_));
                CloseLocked(proto::CloseReason::kProtocolError, SG_TIMEOUT, false, false);
            }
        } else if (now >= expires_at_) {
            CloseLocked(proto::CloseReason::kSessionExpired, SG_SESSION_EXPIRED, true, true);
        } else if (cfg.idle_timeout_ms != 0 && ElapsedMs(now, last_activity_) > cfg.idle_timeout_ms) {
            CloseLocked(proto::CloseReason::kIdleTimeout, SG_TIMEOUT, true, true);
        } else if (phase_ == proto::Phase::kRefreshing &&
                   ElapsedMs(now, reauth_issued_at_) > engine_->auth_context()->config.challenge_ttl_ms) {
            CloseLocked(proto::CloseReason::kAuthFailed, SG_CHALLENGE_EXPIRED, true, true);
        }
    }
    DeliverEvents();
}

// ---- introspection ---------------------------------------------------------------------

void Connection::SnapshotLocked(SessionSnapshot* out, uint64_t now) const
{
    out->handle = handle_;
    out->session_id = outcome_.session_id;
    out->installation_id = outcome_.installation_id;
    out->policy = outcome_.decision.policy;
    out->epoch = epoch_;
    out->granted_features = outcome_.decision.granted_features;
    out->license_expires_at_ms = outcome_.decision.license_expires_at_ms;
    out->expires_in_ms = expires_at_ > now ? expires_at_ - now : 0;
    out->enrolled = outcome_.enrolled;
    out->peer_address = stream_->PeerAddress();
    out->product_id = outcome_.record.product_id.empty() ? outcome_.hello.product_id : outcome_.record.product_id;
    // Registered or verified licenses only; never a raw client claim.
    out->license_id = outcome_.decision.license_id;
    out->license_status = outcome_.decision.license_verified ? LicenseCheck::kValid
                          : out->license_id.empty()          ? LicenseCheck::kNone
                                                             : LicenseCheck::kUnknown;
}

bool Connection::Snapshot(SessionSnapshot* out)
{
    std::lock_guard<std::mutex> lock(mutex_);
    if (!opened_ || closed_) return false;
    SnapshotLocked(out, MonotonicMs());
    return true;
}

bool Connection::IsInstallation(const proto::InstallationId& id)
{
    std::lock_guard<std::mutex> lock(mutex_);
    return opened_ && !closed_ && outcome_.installation_id == id;
}

bool Connection::UsesLicense(const std::string& license_id, const proto::InstallationId* installation)
{
    std::lock_guard<std::mutex> lock(mutex_);
    return opened_ && !closed_ && outcome_.decision.license_id == license_id &&
           (installation == nullptr || outcome_.installation_id == *installation);
}

bool Connection::IsAuthenticated()
{
    std::lock_guard<std::mutex> lock(mutex_);
    return opened_ && !closed_;
}

void Connection::LeaveUnauthenticated() noexcept
{
    if (TakeUnauthenticated()) engine_->ReleaseUnauthenticated();
}

// ---- event delivery --------------------------------------------------------------------

void Connection::DeliverEvents()
{
    for (;;) {
        std::vector<Event> batch;
        {
            std::lock_guard<std::mutex> lock(mutex_);
            if (delivering_ || pending_events_.empty()) return;
            delivering_ = true;
            batch.swap(pending_events_);
            delivering_bytes_ = pending_event_bytes_;
            pending_event_bytes_ = 0;
        }
        const EngineCallbacks& cb = engine_->callbacks();
        for (Event& e : batch) {
            try {
                switch (e.kind) {
                case Event::Kind::kOpened:
                    if (cb.session_opened) {
                        CallbackScope scope;
                        cb.session_opened(e.snapshot);
                    }
                    break;
                case Event::Kind::kMessage:
                    if (cb.message) {
                        CallbackScope scope;
                        cb.message(handle_, e.data.data(), e.data.size(), e.request_id, e.flags);
                    }
                    break;
                case Event::Kind::kClosed:
                    if (cb.session_closed) {
                        CallbackScope scope;
                        cb.session_closed(handle_, e.reason);
                    }
                    break;
                case Event::Kind::kRemove:
                    engine_->OnConnectionClosed(shared_from_this());
                    break;
                }
            } catch (...) {
                // Application callbacks must not throw across the library; ignore.
            }
        }
        bool resume = false;
        bool more = false;
        {
            std::lock_guard<std::mutex> lock(mutex_);
            delivering_ = false;
            delivering_bytes_ = 0;
            if (read_paused_ && !closed_ && pending_event_bytes_ <= kReadPauseBytes) {
                read_paused_ = false;
                resume = true;
            }
            more = !pending_events_.empty();
        }
        // Issued without the lock; a concurrent close simply makes it fail.
        if (resume) IssueRead();
        if (!more) return;
    }
}

}  // namespace sg::server
