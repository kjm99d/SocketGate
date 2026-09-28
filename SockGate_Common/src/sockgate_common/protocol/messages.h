// Message payload codecs for SockGate protocol v1.
//
// Decoders treat input as hostile: every field is range-checked, enums must
// be known, fixed-size fields must have exactly their size, TLV sections
// follow the strict rules of serialization/tlv.h, and trailing bytes are an
// error. Decoders only establish *structural* validity; semantic checks
// (signatures, challenge freshness, authorisation) belong to the handshake.
#pragma once

#include "sockgate_common/core/bytes.h"
#include "sockgate_common/core/status.h"
#include "sockgate_common/crypto/crypto.h"
#include "sockgate_common/protocol/constants.h"

#include <string>

namespace sg::proto {

struct IntegrityReport {
    uint8_t platform = 0;  // 1 = Windows, 2 = Linux, 3 = macOS
    uint32_t observation_flags = 0;
    crypto::Sha256Digest executable_sha256{};
    crypto::Sha256Digest library_sha256{};
    Bytes build_id;  // <= kMaxBuildIdLength
};

struct ClientHello {
    uint16_t version_min = kMinProtocolVersion;
    uint16_t version_max = kMaxProtocolVersion;
    uint16_t client_version_major = 0;
    uint16_t client_version_minor = 0;
    uint16_t client_version_patch = 0;
    Nonce client_nonce{};
    InstallationId installation_id{};
    uint8_t key_algorithm = kKeyAlgorithmEcdsaP256Sha256;
    AuthMode auth_mode = AuthMode::kAuthenticate;
    // Optional extensions (empty / has_* == false means absent).
    std::string product_id;
    std::string product_version;
    std::string license_id;
    bool has_requested_features = false;
    uint64_t requested_features = 0;
    bool has_integrity = false;
    IntegrityReport integrity;
    Bytes enrollment_token_id;  // ENROLL only: token_pub (never the token secret)
    bool has_public_key = false;
    crypto::P256PublicKey public_key{};
};

struct ServerHello {
    uint16_t selected_version = kProtocolVersion;
    Nonce server_nonce{};
    Challenge challenge{};
    uint32_t challenge_ttl_ms = 0;
    uint8_t server_proof_algorithm = kProofAlgorithmNone;
};

struct ClientProof {
    uint8_t signature_algorithm = kKeyAlgorithmEcdsaP256Sha256;
    crypto::P256Signature signature{};
    bool has_enrollment_proof = false;
    crypto::Sha256Digest enrollment_proof{};
};

struct AuthResult {
    AuthResultCode result = AuthResultCode::kRejected;
    SessionPolicy policy = SessionPolicy::kNone;
    uint64_t granted_features = 0;
    uint32_t session_lifetime_ms = 0;
    uint64_t license_expires_at_ms = 0;
    uint8_t server_proof_algorithm = kProofAlgorithmNone;
    bool has_server_signature = false;
    crypto::P256Signature server_signature{};
};

// Length of the AUTH_RESULT payload prefix covered by the server proof
// (everything before the trailing vec16 signature).
constexpr size_t kAuthResultSignedPayloadPrefix = 1 + 1 + 8 + 4 + 8 + 1;

struct PingPong {
    uint64_t opaque = 0;
};

struct ReauthRequest {
    Nonce client_nonce{};
};

struct ReauthChallenge {
    Nonce server_nonce{};
    Challenge challenge{};
    uint32_t challenge_ttl_ms = 0;
};

struct ReauthProof {
    uint8_t signature_algorithm = kKeyAlgorithmEcdsaP256Sha256;
    crypto::P256Signature signature{};
};

struct ReauthResult {
    AuthResultCode result = AuthResultCode::kRejected;
    uint32_t session_lifetime_ms = 0;
    uint32_t new_epoch = 0;
};

struct CloseMessage {
    CloseReason reason = CloseReason::kNormal;
};

Status EncodeIntegrityReport(const IntegrityReport& in, Bytes* out);
Status DecodeIntegrityReport(ByteView in, IntegrityReport* out);

Status EncodeClientHello(const ClientHello& in, Bytes* out);
Status DecodeClientHello(ByteView in, ClientHello* out);

Status EncodeServerHello(const ServerHello& in, Bytes* out);
Status DecodeServerHello(ByteView in, ServerHello* out);

Status EncodeClientProof(const ClientProof& in, Bytes* out);
Status DecodeClientProof(ByteView in, ClientProof* out);

Status EncodeAuthResult(const AuthResult& in, Bytes* out);
Status DecodeAuthResult(ByteView in, AuthResult* out);

Status EncodePingPong(const PingPong& in, Bytes* out);
Status DecodePingPong(ByteView in, PingPong* out);

Status EncodeReauthRequest(const ReauthRequest& in, Bytes* out);
Status DecodeReauthRequest(ByteView in, ReauthRequest* out);

Status EncodeReauthChallenge(const ReauthChallenge& in, Bytes* out);
Status DecodeReauthChallenge(ByteView in, ReauthChallenge* out);

Status EncodeReauthProof(const ReauthProof& in, Bytes* out);
Status DecodeReauthProof(ByteView in, ReauthProof* out);

Status EncodeReauthResult(const ReauthResult& in, Bytes* out);
Status DecodeReauthResult(ByteView in, ReauthResult* out);

Status EncodeClose(const CloseMessage& in, Bytes* out);
Status DecodeClose(ByteView in, CloseMessage* out);

}  // namespace sg::proto
