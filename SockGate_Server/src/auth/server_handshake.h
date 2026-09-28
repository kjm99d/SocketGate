// Server side of the SockGate authentication handshake (sans-IO).
//
//   OnClientHello()  -> SERVER_HELLO (fresh session id, nonce, single-use challenge)
//                       or AUTH_RESULT(UNSUPPORTED_VERSION)
//   OnClientProof()  -> AUTH_RESULT (OK or a generic REJECTED)
//
// Rejections are deliberately indistinguishable on the wire; the precise
// reason is available through failure_reason() for server logs.
#pragma once

#include "auth/authorizer.h"
#include "storage/client_registry.h"

#include "sockgate_common/core/bytes.h"
#include "sockgate_common/protocol/frame.h"
#include "sockgate_common/protocol/messages.h"
#include "sockgate_common/protocol/rules.h"

#include <functional>
#include <memory>
#include <string>

namespace sg::server {

struct EnrollmentRequest {
    proto::InstallationId installation_id{};
    crypto::P256PublicKey public_key{};
    Bytes token_pub;          // public part of the enrollment token as sent by the client
    std::string product_id;   // client claims from CLIENT_HELLO (may be empty)
    std::string license_id;
    std::string peer_address;
};

// External enrollment validation: returns OK and the token's K_tok, or an
// error to reject. It is responsible for any single-use tracking of its own.
using EnrollValidator = std::function<Status(const EnrollmentRequest&, crypto::Sha256Digest* k_tok)>;

struct HandshakeConfig {
    uint32_t challenge_ttl_ms = 30'000;
    uint32_t default_session_lifetime_ms = 3'600'000;
    uint32_t max_session_lifetime_ms = 7u * 24 * 3'600'000;
    uint16_t min_protocol_version = proto::kMinProtocolVersion;
    uint16_t max_protocol_version = proto::kMaxProtocolVersion;
    bool allow_enrollment = false;
    SecureBytes token_key;  // >= 32 bytes, enables built-in enrollment tokens
    std::shared_ptr<const crypto::SoftwareP256Key> proof_key;  // optional server proof
    EnrollValidator enroll_validator;
    // Injectable clocks (tests); default to the real monotonic / wall clocks.
    std::function<uint64_t()> monotonic_ms;
    std::function<uint64_t()> unix_ms;
};

// Shared by all connections of a server.
struct ServerAuthContext {
    HandshakeConfig config;
    IClientRegistry* registry = nullptr;
    IAuthorizer* authorizer = nullptr;
    crypto::P256PublicKey dummy_key{};  // verification target for unknown installations (timing)

    static Status Create(HandshakeConfig config, IClientRegistry* registry, IAuthorizer* authorizer,
                         std::shared_ptr<ServerAuthContext>* out);
    uint64_t Now() const;
    uint64_t UnixNow() const;
};

struct HandshakeOutcome {
    proto::SessionId session_id{};
    proto::InstallationId installation_id{};
    crypto::Sha256Digest transcript_hash{};  // TH1
    crypto::Sha256Digest channel_binding{};
    uint16_t protocol_version = proto::kProtocolVersion;
    ClientRecord record;
    AuthorizationDecision decision;
    uint32_t session_lifetime_ms = 0;
    bool enrolled = false;
    proto::ClientHello hello;
};

class ServerHandshake {
public:
    explicit ServerHandshake(std::shared_ptr<const ServerAuthContext> context);
    ~ServerHandshake();

    ServerHandshake(const ServerHandshake&) = delete;
    ServerHandshake& operator=(const ServerHandshake&) = delete;

    // OK: *reply holds SERVER_HELLO. SG_VERSION_MISMATCH: *reply holds
    // AUTH_RESULT(UNSUPPORTED_VERSION), close afterwards. Any other error:
    // protocol violation, close without reply.
    Status OnClientHello(const proto::DecodedFrame& frame, const crypto::Sha256Digest& channel_binding,
                         const std::string& peer_address, Bytes* reply);

    // OK: authenticated, *reply holds AUTH_RESULT(OK), *outcome filled.
    // SG_AUTH_FAILED: *reply holds AUTH_RESULT(REJECTED), close afterwards.
    // Other errors: protocol violation, close without reply.
    Status OnClientProof(const proto::DecodedFrame& frame, Bytes* reply, HandshakeOutcome* outcome);

    // Replaces a successful outcome with AUTH_RESULT(REJECTED) in *reply;
    // returns SG_AUTH_FAILED.
    Status Reject(const std::string& reason, Bytes* reply);

    void set_session_handle(uint64_t handle) noexcept { session_handle_ = handle; }
    proto::Phase phase() const noexcept { return phase_; }
    const std::string& failure_reason() const noexcept { return failure_reason_; }
    const proto::SessionId& session_id() const noexcept { return session_id_; }
    const proto::InstallationId& claimed_installation_id() const noexcept { return hello_.installation_id; }

private:
    Status VerifyEnrollment(const proto::ClientProof& proof, const crypto::Sha256Digest& th1,
                            const Bytes& signed_data, ClientRecord* record);
    Status BuildAuthResult(const AuthorizationDecision& decision, uint32_t lifetime_ms,
                           const proto::DecodedFrame& proof_frame, const crypto::Sha256Digest& th1, Bytes* reply);

    std::shared_ptr<const ServerAuthContext> ctx_;
    proto::Phase phase_ = proto::Phase::kAwaitClientHello;
    std::string failure_reason_;

    std::string peer_address_;
    proto::ClientHello hello_;
    Bytes client_hello_frame_;
    Bytes server_hello_frame_;
    crypto::Sha256Digest channel_binding_{};
    proto::SessionId session_id_{};
    proto::Challenge challenge_{};
    uint64_t challenge_issued_at_ = 0;
    bool challenge_consumed_ = false;
    uint16_t selected_version_ = 0;
    uint64_t session_handle_ = 0;
};

// Generates a random, non-zero session id.
Status GenerateSessionId(proto::SessionId* out);

}  // namespace sg::server
