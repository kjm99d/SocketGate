#include "auth/server_handshake.h"

#include "sockgate_common/core/clock.h"
#include "sockgate_common/protocol/enrollment_token.h"
#include "sockgate_common/protocol/transcript.h"

#include <algorithm>

namespace sg::server {
namespace {

// Tolerated clock skew for token "issued_at" in the future.
constexpr uint64_t kTokenIssueSkewMs = 5 * 60 * 1000;

bool IsZero(const proto::SessionId& id)
{
    return std::all_of(id.begin(), id.end(), [](uint8_t b) { return b == 0; });
}

}  // namespace

Status GenerateSessionId(proto::SessionId* out)
{
    do {
        SG_TRY(crypto::RandomArray(out));
    } while (IsZero(*out));
    return OkStatus();
}

Status ServerAuthContext::Create(HandshakeConfig config, IClientRegistry* registry, IAuthorizer* authorizer,
                                 std::shared_ptr<ServerAuthContext>* out)
{
    if (registry == nullptr || authorizer == nullptr || out == nullptr) return SG_INVALID_ARGUMENT;
    if (config.challenge_ttl_ms == 0 || config.default_session_lifetime_ms == 0 ||
        config.max_session_lifetime_ms < config.default_session_lifetime_ms ||
        config.min_protocol_version == 0 || config.min_protocol_version > config.max_protocol_version) {
        return SG_INVALID_ARGUMENT;
    }
    if (!config.token_key.empty() && config.token_key.size() < 32) return SG_INVALID_ARGUMENT;
    auto ctx = std::make_shared<ServerAuthContext>();
    ctx->config = std::move(config);
    ctx->registry = registry;
    ctx->authorizer = authorizer;
    // A throw-away key: signatures checked against it always fail, but cost
    // the same as a real verification.
    std::unique_ptr<crypto::SoftwareP256Key> dummy;
    SG_TRY(crypto::SoftwareP256Key::Generate(&dummy));
    SG_TRY(dummy->PublicKey(&ctx->dummy_key));
    *out = std::move(ctx);
    return OkStatus();
}

uint64_t ServerAuthContext::Now() const { return config.monotonic_ms ? config.monotonic_ms() : MonotonicMs(); }
uint64_t ServerAuthContext::UnixNow() const { return config.unix_ms ? config.unix_ms() : UnixTimeMs(); }

ServerHandshake::ServerHandshake(std::shared_ptr<const ServerAuthContext> context) : ctx_(std::move(context)) {}

ServerHandshake::~ServerHandshake()
{
    SecureZero(challenge_.data(), challenge_.size());
    SecureZero(channel_binding_.data(), channel_binding_.size());
}

Status ServerHandshake::OnClientHello(const proto::DecodedFrame& frame, const crypto::Sha256Digest& channel_binding,
                                      const std::string& peer_address, Bytes* reply)
{
    if (reply == nullptr) return SG_INVALID_ARGUMENT;
    reply->clear();
    if (phase_ != proto::Phase::kAwaitClientHello) return SG_PROTOCOL_ERROR;
    phase_ = proto::Phase::kClosed;  // until proven otherwise

    const proto::FrameHeader& h = frame.header();
    if (h.type != proto::MessageType::kClientHello || h.sequence != 1 || !IsZero(h.session_id)) {
        return SG_PROTOCOL_ERROR;
    }
    SG_TRY(proto::DecodeClientHello(frame.payload(), &hello_));
    peer_address_ = peer_address;

    const HandshakeConfig& cfg = ctx_->config;
    const uint16_t high = std::min(hello_.version_max, cfg.max_protocol_version);
    const uint16_t low = std::max(hello_.version_min, cfg.min_protocol_version);
    if (high < low) {
        failure_reason_ = "unsupported protocol version";
        proto::AuthResult result;
        result.result = proto::AuthResultCode::kUnsupportedVersion;
        Bytes payload;
        SG_TRY(proto::EncodeAuthResult(result, &payload));
        proto::FrameHeader rh;
        rh.type = proto::MessageType::kAuthResult;
        rh.sequence = 1;  // replaces SERVER_HELLO; no session id is assigned
        SG_TRY(proto::EncodeFrame(rh, payload, ByteView(), reply));
        return SG_VERSION_MISMATCH;
    }
    selected_version_ = high;

    // Challenge is issued even for unknown installations (no enumeration oracle).
    proto::ServerHello sh;
    sh.selected_version = selected_version_;
    SG_TRY(crypto::RandomArray(&sh.server_nonce));
    SG_TRY(crypto::RandomArray(&challenge_));
    sh.challenge = challenge_;
    sh.challenge_ttl_ms = cfg.challenge_ttl_ms;
    sh.server_proof_algorithm = cfg.proof_key ? proto::kProofAlgorithmEcdsaP256Sha256 : proto::kProofAlgorithmNone;
    SG_TRY(GenerateSessionId(&session_id_));

    Bytes payload;
    SG_TRY(proto::EncodeServerHello(sh, &payload));
    proto::FrameHeader sh_header;
    sh_header.type = proto::MessageType::kServerHello;
    sh_header.session_id = session_id_;
    sh_header.sequence = 1;
    server_hello_frame_.clear();
    SG_TRY(proto::EncodeFrame(sh_header, payload, ByteView(), &server_hello_frame_));

    client_hello_frame_ = frame.wire().ToBytes();
    channel_binding_ = channel_binding;
    challenge_issued_at_ = ctx_->Now();
    challenge_consumed_ = false;
    *reply = server_hello_frame_;
    phase_ = proto::Phase::kAwaitClientProof;
    return OkStatus();
}

Status ServerHandshake::Reject(const std::string& reason, Bytes* reply)
{
    failure_reason_ = reason;
    phase_ = proto::Phase::kClosed;
    proto::AuthResult result;
    result.result = proto::AuthResultCode::kRejected;
    Bytes payload;
    SG_TRY(proto::EncodeAuthResult(result, &payload));
    proto::FrameHeader h;
    h.type = proto::MessageType::kAuthResult;
    h.session_id = session_id_;
    h.sequence = 2;
    reply->clear();
    SG_TRY(proto::EncodeFrame(h, payload, ByteView(), reply));
    return SG_AUTH_FAILED;
}

Status ServerHandshake::VerifyEnrollment(const proto::ClientProof& proof, const crypto::Sha256Digest& th1,
                                         const Bytes& signed_data, ClientRecord* record)
{
    const HandshakeConfig& cfg = ctx_->config;
    if (!cfg.allow_enrollment) {
        failure_reason_ = "enrollment disabled";
        return SG_AUTH_FAILED;
    }

    // 1. K_tok: from the external validator or re-derived from the server secret.
    crypto::Sha256Digest k_tok{};
    proto::EnrollmentClaims claims;
    const bool builtin = !cfg.enroll_validator;
    if (builtin) {
        if (cfg.token_key.size() < 32) {
            failure_reason_ = "no enrollment token key configured";
            return SG_AUTH_FAILED;
        }
        if (!proto::DecodeTokenPublic(hello_.enrollment_token_id, &claims).ok()) {
            failure_reason_ = "malformed enrollment token";
            return SG_AUTH_FAILED;
        }
        SG_TRY(proto::DeriveEnrollmentKey(cfg.token_key, hello_.enrollment_token_id, &k_tok));
    } else {
        EnrollmentRequest request;
        request.installation_id = hello_.installation_id;
        request.public_key = hello_.public_key;
        request.token_pub = hello_.enrollment_token_id;
        request.product_id = hello_.product_id;
        request.license_id = hello_.license_id;
        request.peer_address = peer_address_;
        if (!cfg.enroll_validator(request, &k_tok).ok()) {
            failure_reason_ = "enrollment rejected by validator";
            return SG_AUTH_FAILED;
        }
    }

    // 2. Channel-bound proof of token possession (cheap, before the signature).
    crypto::Sha256Digest expected;
    const Status mac_status = proto::ComputeEnrollmentProof(k_tok, th1, &expected);
    SecureZero(k_tok.data(), k_tok.size());
    SG_TRY(mac_status);
    if (!ConstantTimeEqual(expected.data(), expected.size(), proof.enrollment_proof.data(),
                           proof.enrollment_proof.size())) {
        failure_reason_ = "enrollment proof mismatch";
        return SG_AUTH_FAILED;
    }

    // 3. Token claims (built-in tokens only; external validators check their own).
    if (builtin) {
        const uint64_t now = ctx_->UnixNow();
        if (now >= claims.expires_at_ms) {
            failure_reason_ = "enrollment token expired";
            return SG_AUTH_FAILED;
        }
        if (claims.issued_at_ms > now + kTokenIssueSkewMs) {
            failure_reason_ = "enrollment token issued in the future";
            return SG_AUTH_FAILED;
        }
        if ((!hello_.product_id.empty() && hello_.product_id != claims.product_id) ||
            (!hello_.license_id.empty() && hello_.license_id != claims.license_id)) {
            failure_reason_ = "enrollment claims mismatch";
            return SG_AUTH_FAILED;
        }
    }

    // 4. Installation id must be derived from the enrolled key.
    proto::InstallationId derived;
    if (!crypto::ValidateP256PublicKey(hello_.public_key).ok() ||
        !proto::DeriveInstallationId(hello_.public_key, &derived).ok() || derived != hello_.installation_id) {
        failure_reason_ = "invalid enrollment key";
        return SG_AUTH_FAILED;
    }

    // 5. Proof of possession of the private key.
    if (!crypto::VerifyP256(hello_.public_key, signed_data, proof.signature).ok()) {
        failure_reason_ = "invalid signature";
        return SG_AUTH_FAILED;
    }

    // 6. Atomically consume the token and register the installation.
    record->installation_id = hello_.installation_id;
    record->public_key = hello_.public_key;
    record->status = ClientStatus::kActive;
    // Built-in tokens carry server-issued bindings. An external validator only
    // approves the token: the client's license claim is not turned into a
    // binding here (it goes through authorization like any claim, i.e. it is
    // only bound by license activation).
    record->product_id = builtin ? claims.product_id : hello_.product_id;
    record->license_id = builtin ? claims.license_id : std::string();
    record->created_at_ms = ctx_->UnixNow();
    proto::TokenId token_id{};
    uint64_t token_expiry = claims.expires_at_ms;
    if (builtin) {
        token_id = claims.token_id;
    } else {
        crypto::Sha256Digest digest;
        SG_TRY(crypto::Sha256(hello_.enrollment_token_id, &digest));
        std::copy(digest.begin(), digest.begin() + static_cast<std::ptrdiff_t>(token_id.size()), token_id.begin());
        token_expiry = 0;
    }
    const Status st = ctx_->registry->EnrollAtomically(*record, token_id, token_expiry);
    if (!st.ok()) {
        failure_reason_ = st == SG_ALREADY_EXISTS ? "token already used or installation exists" : "registry failure";
        return SG_AUTH_FAILED;
    }
    return OkStatus();
}

Status ServerHandshake::OnClientProof(const proto::DecodedFrame& frame, Bytes* reply, HandshakeOutcome* outcome)
{
    if (reply == nullptr || outcome == nullptr) return SG_INVALID_ARGUMENT;
    reply->clear();
    if (phase_ != proto::Phase::kAwaitClientProof) return SG_PROTOCOL_ERROR;
    phase_ = proto::Phase::kClosed;  // exactly one authentication attempt per connection

    const proto::FrameHeader& h = frame.header();
    if (h.type != proto::MessageType::kClientProof || h.sequence != 2 || h.session_id != session_id_) {
        return SG_PROTOCOL_ERROR;
    }
    proto::ClientProof proof;
    SG_TRY(proto::DecodeClientProof(frame.payload(), &proof));
    const bool enroll = hello_.auth_mode == proto::AuthMode::kEnroll;
    if (proof.has_enrollment_proof != enroll) return SG_PROTOCOL_ERROR;

    // Consume the challenge before any verification: it can never be retried.
    const bool challenge_fresh =
        !challenge_consumed_ && ctx_->Now() - challenge_issued_at_ <= ctx_->config.challenge_ttl_ms;
    challenge_consumed_ = true;

    crypto::Sha256Digest th1;
    SG_TRY(proto::ComputeTranscriptHash(selected_version_, channel_binding_, client_hello_frame_, server_hello_frame_,
                                        &th1));
    const Bytes signed_data = proto::SignedData(proto::kClientProofContext, th1);

    ClientRecord record;
    if (enroll) {
        if (!challenge_fresh) return Reject("challenge expired", reply);
        const Status st = VerifyEnrollment(proof, th1, signed_data, &record);
        if (!st.ok()) return Reject(failure_reason_.empty() ? "enrollment failed" : failure_reason_, reply);
        outcome->enrolled = true;
    } else {
        const Status found = ctx_->registry->Find(hello_.installation_id, &record);
        const bool usable = found.ok() && record.status == ClientStatus::kActive &&
                            record.key_algorithm == proof.signature_algorithm;
        // Unknown or revoked installations are verified against a dummy key so
        // that the response time does not reveal registry membership.
        const crypto::P256PublicKey& key = usable ? record.public_key : ctx_->dummy_key;
        const bool signature_ok = crypto::VerifyP256(key, signed_data, proof.signature).ok();
        if (!found.ok()) return Reject("unknown installation", reply);
        if (record.status != ClientStatus::kActive) return Reject("installation revoked", reply);
        if (!usable) return Reject("key algorithm mismatch", reply);
        if (!signature_ok) return Reject("invalid signature", reply);
        if (!challenge_fresh) return Reject("challenge expired", reply);
    }

    // Server-side authorisation: the client's claims never grant anything by themselves.
    AuthorizationRequest request;
    request.installation_id = hello_.installation_id;
    request.record = &record;
    request.mode = hello_.auth_mode;
    request.session_handle = session_handle_;
    request.product_id = hello_.product_id;
    request.product_version = hello_.product_version;
    request.license_id = hello_.license_id;
    request.has_requested_features = hello_.has_requested_features;
    request.requested_features = hello_.requested_features;
    request.client_version_major = hello_.client_version_major;
    request.client_version_minor = hello_.client_version_minor;
    request.client_version_patch = hello_.client_version_patch;
    request.has_integrity = hello_.has_integrity;
    request.integrity = hello_.integrity;
    request.peer_address = peer_address_;
    AuthorizationDecision decision;
    const Status authz = ctx_->authorizer->Authorize(request, &decision);
    if (!authz.ok() || !decision.allow) {
        return Reject(decision.deny_reason.empty() ? "authorization denied" : "authorization denied: " + decision.deny_reason,
                      reply);
    }
    if (decision.policy != proto::SessionPolicy::kNormal && decision.policy != proto::SessionPolicy::kRestricted) {
        return Reject("invalid authorization policy", reply);
    }

    const HandshakeConfig& cfg = ctx_->config;
    uint64_t lifetime = decision.session_lifetime_ms != 0 ? decision.session_lifetime_ms : cfg.default_session_lifetime_ms;
    lifetime = std::min<uint64_t>(lifetime, cfg.max_session_lifetime_ms);
    if (decision.license_expires_at_ms != 0) {
        const uint64_t now = ctx_->UnixNow();
        if (decision.license_expires_at_ms <= now) return Reject("license expired", reply);
        lifetime = std::min<uint64_t>(lifetime, decision.license_expires_at_ms - now);
    }
    const uint32_t lifetime_ms = static_cast<uint32_t>(std::max<uint64_t>(lifetime, 1));

    SG_TRY(BuildAuthResult(decision, lifetime_ms, frame, th1, reply));

    outcome->session_id = session_id_;
    outcome->installation_id = hello_.installation_id;
    outcome->transcript_hash = th1;
    outcome->channel_binding = channel_binding_;
    outcome->protocol_version = selected_version_;
    outcome->record = record;
    outcome->decision = decision;
    outcome->session_lifetime_ms = lifetime_ms;
    outcome->hello = hello_;
    phase_ = proto::Phase::kActive;
    return OkStatus();
}

Status ServerHandshake::BuildAuthResult(const AuthorizationDecision& decision, uint32_t lifetime_ms,
                                        const proto::DecodedFrame& proof_frame, const crypto::Sha256Digest& th1,
                                        Bytes* reply)
{
    const auto& proof_key = ctx_->config.proof_key;
    proto::AuthResult result;
    result.result = proto::AuthResultCode::kOk;
    result.policy = decision.policy;
    result.granted_features = decision.granted_features;
    result.session_lifetime_ms = lifetime_ms;
    result.license_expires_at_ms = decision.license_expires_at_ms;
    result.server_proof_algorithm = proof_key ? proto::kProofAlgorithmEcdsaP256Sha256 : proto::kProofAlgorithmNone;
    result.has_server_signature = proof_key != nullptr;  // placeholder signature, patched below

    Bytes payload;
    SG_TRY(proto::EncodeAuthResult(result, &payload));
    proto::FrameHeader h;
    h.type = proto::MessageType::kAuthResult;
    h.session_id = session_id_;
    h.sequence = 2;
    reply->clear();
    SG_TRY(proto::EncodeFrame(h, payload, ByteView(), reply));

    if (proof_key) {
        const size_t prefix = proto::kHeaderSize + proto::kAuthResultSignedPayloadPrefix;
        crypto::Sha256Digest th2;
        SG_TRY(proto::ComputeServerTranscriptHash(th1, proof_frame.wire(), ByteView(reply->data(), prefix), &th2));
        crypto::P256Signature signature;
        SG_TRY(proof_key->Sign(proto::SignedData(proto::kServerProofContext, th2), &signature));
        // Layout after the prefix: u16 length (64) then the signature.
        std::copy(signature.begin(), signature.end(), reply->begin() + static_cast<std::ptrdiff_t>(prefix + 2));
    }
    return OkStatus();
}

}  // namespace sg::server
