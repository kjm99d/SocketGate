// Client side of the SockGate authentication handshake (sans-IO).
//
//   Start()          -> CLIENT_HELLO frame
//   OnServerHello()  -> CLIENT_PROOF frame (signature over the channel-bound transcript)
//   OnAuthResult()   -> outcome (+ optional server proof verification)
//
// The caller moves frames over TLS and supplies the channel binding value of
// its own TLS connection.
#pragma once

#include "crypto/key_store.h"

#include "sockgate_common/protocol/frame.h"
#include "sockgate_common/protocol/messages.h"
#include "sockgate_common/protocol/rules.h"

#include <string>
#include <vector>

namespace sg::client {

struct ClientHandshakeConfig {
    uint16_t version_min = proto::kMinProtocolVersion;
    uint16_t version_max = proto::kMaxProtocolVersion;
    uint16_t client_version_major = 0;
    uint16_t client_version_minor = 0;
    uint16_t client_version_patch = 0;
    std::string product_id;
    std::string product_version;
    std::string license_id;
    bool has_requested_features = false;
    uint64_t requested_features = 0;
    bool has_integrity = false;
    proto::IntegrityReport integrity;
    // When non-empty the server MUST prove possession of one of these keys.
    std::vector<crypto::P256PublicKey> server_proof_keys;
};

struct EnrollmentMaterial {
    Bytes token_pub;          // sent in CLIENT_HELLO
    crypto::Sha256Digest k_tok{};  // never sent; used for the channel-bound proof
};

struct ClientHandshakeResult {
    proto::SessionId session_id{};
    crypto::Sha256Digest transcript_hash{};  // TH1, input to the channel key schedule
    proto::AuthResult auth_result;
    uint16_t protocol_version = proto::kProtocolVersion;
};

class ClientHandshake {
public:
    ClientHandshake(ClientHandshakeConfig config, IKeyStore& key_store, std::string key_name);
    ~ClientHandshake();

    ClientHandshake(const ClientHandshake&) = delete;
    ClientHandshake& operator=(const ClientHandshake&) = delete;

    // enrollment == nullptr: AUTHENTICATE mode.
    Status Start(const crypto::Sha256Digest& channel_binding, const EnrollmentMaterial* enrollment, Bytes* frame_out);

    Status OnServerHello(const proto::DecodedFrame& frame, Bytes* frame_out);

    // OK: authenticated. Otherwise SG_SERVER_REJECTED, SG_VERSION_MISMATCH,
    // SG_INVALID_SIGNATURE (server proof) or SG_PROTOCOL_ERROR.
    Status OnAuthResult(const proto::DecodedFrame& frame, ClientHandshakeResult* out);

    proto::Phase phase() const noexcept { return phase_; }

private:
    ClientHandshakeConfig config_;
    IKeyStore& key_store_;
    const std::string key_name_;

    proto::Phase phase_ = proto::Phase::kAwaitServerHello;
    bool started_ = false;
    bool enroll_ = false;
    crypto::Sha256Digest channel_binding_{};
    crypto::Sha256Digest k_tok_{};
    Bytes client_hello_frame_;
    Bytes client_proof_frame_;
    proto::SessionId session_id_{};
    uint16_t selected_version_ = 0;
    uint8_t server_proof_algorithm_ = proto::kProofAlgorithmNone;
    crypto::Sha256Digest th1_{};
};

}  // namespace sg::client
