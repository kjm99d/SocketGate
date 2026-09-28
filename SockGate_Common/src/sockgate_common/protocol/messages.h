#pragma once
/**
 * @file
 * @brief Message payload codecs for SockGate protocol v1.
 *
 * Decoders treat input as hostile: every field is range-checked, enums must
 * be known, fixed-size fields must have exactly their size, TLV sections
 * follow the strict rules of serialization/tlv.h, and trailing bytes are an
 * error. Decoders only establish *structural* validity; semantic checks
 * (signatures, challenge freshness, authorisation) belong to the handshake.
 *
 * Conventions for every Encode / Decode pair below:
 * - Integers are big endian; `vec16` is a u16 length followed by that many bytes; a TLV section is
 *   `u16 total_length` followed by `{u16 type, u16 length, value}` entries (at most 16, no duplicate
 *   types, lengths must add up exactly). Unknown TLV types are length-validated and ignored.
 * - Encoders append to @c out (which must not be nullptr). Except for PING/PONG and REAUTH_REQUEST, they
 *   re-parse their own output with the matching decoder; if that fails the output is truncated back to its
 *   original size and SG_INVALID_ARGUMENT is returned, so the library never emits a message its peer is
 *   required to reject.
 * - Decoders read exactly the payload given and return SG_PROTOCOL_ERROR for every structural violation
 *   (truncation, bad length, unknown enum value, violated field rule, trailing bytes). @c out must not be
 *   nullptr; on failure it may hold partially decoded fields.
 */

#include "sockgate_common/core/bytes.h"
#include "sockgate_common/core/status.h"
#include "sockgate_common/crypto/crypto.h"
#include "sockgate_common/protocol/constants.h"

#include <string>

namespace sg::proto {

/**
 * @brief INTEGRITY_REPORT (CLIENT_HELLO TLV 5).
 *
 * Wire: u8 report_version (= 1) || u8 platform || u32 observation_flags || bytes32 executable_sha256 ||
 * bytes32 library_sha256 || vec16 build_id.
 *
 * @warning Client-reported observations: nothing in them is verified, so they are never trusted to raise
 *          trust (see sockgate/types.h).
 */
struct IntegrityReport {
    uint8_t platform = 0;  ///< 1 = Windows, 2 = Linux, 3 = macOS
    uint32_t observation_flags = 0;  ///< SG_INTEGRITY_* bits (sockgate/types.h); unknown bits are rejected.
    crypto::Sha256Digest executable_sha256{};  ///< SHA-256 of the client executable, as reported by the client.
    crypto::Sha256Digest library_sha256{};     ///< SHA-256 of the SockGate client library module, as reported.
    Bytes build_id;  ///< <= kMaxBuildIdLength
};

/**
 * @brief CLIENT_HELLO payload.
 *
 * Wire: u16 version_min || u16 version_max || u16 client_version_major || u16 client_version_minor ||
 * u16 client_version_patch || bytes32 client_nonce || bytes16 installation_id || u8 key_algorithm ||
 * u8 auth_mode || TLV extensions (tlv::kProductId ... tlv::kPublicKey).
 *
 * @warning Every field is a client claim. The decoder checks only structure (PUBLIC_KEY: 65 bytes starting
 *          with 0x04, not curve membership); the handshake verifies the rest.
 */
struct ClientHello {
    uint16_t version_min = kMinProtocolVersion;  ///< Lowest acceptable protocol version; 0 < min <= max.
    uint16_t version_max = kMaxProtocolVersion;  ///< Highest acceptable protocol version.
    uint16_t client_version_major = 0;  ///< Client version set by the application (not validated by the codec).
    uint16_t client_version_minor = 0;  ///< Client version, minor.
    uint16_t client_version_patch = 0;  ///< Client version, patch.
    Nonce client_nonce{};               ///< 32-byte client nonce.
    /// Installation id, derived from the installation public key (DeriveInstallationId()); in ENROLL mode the
    /// server verifies that relation.
    InstallationId installation_id{};
    uint8_t key_algorithm = kKeyAlgorithmEcdsaP256Sha256;  ///< Must be kKeyAlgorithmEcdsaP256Sha256.
    AuthMode auth_mode = AuthMode::kAuthenticate;          ///< Authenticate or enroll.
    // Optional extensions (empty / has_* == false means absent).
    std::string product_id;       ///< PRODUCT_ID TLV; 1..kMaxProductIdLength bytes, strict UTF-8, no controls.
    std::string product_version;  ///< PRODUCT_VERSION TLV; 1..kMaxProductVersionLength bytes.
    std::string license_id;       ///< LICENSE_ID TLV; 1..kMaxLicenseIdLength bytes.
    bool has_requested_features = false;  ///< REQUESTED_FEATURES TLV present.
    uint64_t requested_features = 0;      ///< Requested feature bitmask.
    bool has_integrity = false;           ///< INTEGRITY_REPORT TLV present.
    IntegrityReport integrity;            ///< Integrity report (encoded value <= kMaxIntegrityReportLength).
    /// ENROLL only: token_pub (never the token secret); 1..kMaxEnrollmentTokenIdLength bytes. Required in
    /// ENROLL mode, forbidden in AUTHENTICATE mode.
    Bytes enrollment_token_id;
    bool has_public_key = false;          ///< PUBLIC_KEY TLV present; required in ENROLL, forbidden otherwise.
    crypto::P256PublicKey public_key{};   ///< SEC1 uncompressed P-256 point (0x04 || X || Y).
};

/**
 * @brief SERVER_HELLO payload. The frame header carries the new session id.
 *
 * Wire: u16 selected_version || bytes32 server_nonce || bytes32 challenge || u32 challenge_ttl_ms ||
 * u8 server_proof_algorithm || TLV extensions (none defined in v1; always sent empty).
 */
struct ServerHello {
    uint16_t selected_version = kProtocolVersion;  ///< Selected protocol version; must not be 0.
    Nonce server_nonce{};                          ///< 32-byte server nonce.
    Challenge challenge{};                         ///< 32-byte challenge signed (via TH1) by CLIENT_PROOF.
    uint32_t challenge_ttl_ms = 0;                 ///< Challenge validity in milliseconds; must not be 0.
    uint8_t server_proof_algorithm = kProofAlgorithmNone;  ///< kProofAlgorithmNone or ...EcdsaP256Sha256.
};

/**
 * @brief CLIENT_PROOF payload.
 *
 * Wire: u8 signature_algorithm || vec16 signature (exactly 64 bytes) || TLV extensions (tlv::kEnrollmentProof).
 * The signature covers SignedData(kClientProofContext, TH1).
 */
struct ClientProof {
    uint8_t signature_algorithm = kKeyAlgorithmEcdsaP256Sha256;  ///< Must be kKeyAlgorithmEcdsaP256Sha256.
    crypto::P256Signature signature{};    ///< ECDSA P-256 signature, IEEE P1363 r || s (64 bytes).
    /// ENROLLMENT_PROOF TLV present. The codec does not tie it to the auth mode; the handshake requires it
    /// in ENROLL mode and forbids it otherwise.
    bool has_enrollment_proof = false;
    crypto::Sha256Digest enrollment_proof{};  ///< ComputeEnrollmentProof() value (32 bytes).
};

/**
 * @brief AUTH_RESULT payload.
 *
 * Wire: u8 result || u8 policy || u64 granted_features || u32 session_lifetime_ms ||
 * u64 license_expires_at_ms || u8 server_proof_algorithm || vec16 server_signature (length 0 when the
 * algorithm is none, 64 otherwise). No TLV section.
 *
 * With result OK, policy must not be kNone and session_lifetime_ms must not be 0. With any other result,
 * every other field is 0 / none and there is no signature (a rejection never carries session data).
 */
struct AuthResult {
    AuthResultCode result = AuthResultCode::kRejected;  ///< Outcome.
    SessionPolicy policy = SessionPolicy::kNone;        ///< Session policy (kNone unless OK).
    uint64_t granted_features = 0;                      ///< Granted feature bitmask.
    uint32_t session_lifetime_ms = 0;                   ///< Session lifetime in milliseconds.
    uint64_t license_expires_at_ms = 0;                 ///< License expiry, Unix epoch milliseconds; 0 = none.
    /// Must equal the SERVER_HELLO value (checked by the client handshake, not by the codec).
    uint8_t server_proof_algorithm = kProofAlgorithmNone;
    bool has_server_signature = false;  ///< Set exactly when server_proof_algorithm is ECDSA P-256.
    /// ECDSA P-256 signature (P1363) over SignedData(kServerProofContext, TH2).
    crypto::P256Signature server_signature{};
};

/**
 * @brief Length of the AUTH_RESULT payload prefix covered by the server proof
 * (everything before the trailing vec16 signature).
 *
 * result(1) + policy(1) + granted_features(8) + session_lifetime_ms(4) + license_expires_at_ms(8) +
 * server_proof_algorithm(1) = 23 bytes.
 */
constexpr size_t kAuthResultSignedPayloadPrefix = 1 + 1 + 8 + 4 + 8 + 1;

/** @brief PING / PONG payload: exactly one u64. */
struct PingPong {
    uint64_t opaque = 0;  ///< Opaque value; a PONG echoes the PING's value.
};

/** @brief REAUTH_REQUEST payload: exactly bytes32 client_nonce. */
struct ReauthRequest {
    Nonce client_nonce{};  ///< 32-byte client nonce.
};

/** @brief REAUTH_CHALLENGE payload: bytes32 server_nonce || bytes32 challenge || u32 challenge_ttl_ms. */
struct ReauthChallenge {
    Nonce server_nonce{};           ///< 32-byte server nonce.
    Challenge challenge{};          ///< 32-byte challenge.
    uint32_t challenge_ttl_ms = 0;  ///< Challenge validity in milliseconds; must not be 0.
};

/**
 * @brief REAUTH_PROOF payload: u8 signature_algorithm || vec16 signature (64 bytes).
 *
 * The signature covers SignedData(kReauthProofContext, THr).
 */
struct ReauthProof {
    uint8_t signature_algorithm = kKeyAlgorithmEcdsaP256Sha256;  ///< Must be kKeyAlgorithmEcdsaP256Sha256.
    crypto::P256Signature signature{};  ///< ECDSA P-256 signature, IEEE P1363 r || s.
};

/**
 * @brief REAUTH_RESULT payload: u8 result || u32 session_lifetime_ms || u32 new_epoch.
 *
 * result is never kUnsupportedVersion. With OK, session_lifetime_ms must not be 0; otherwise
 * session_lifetime_ms and new_epoch are 0.
 */
struct ReauthResult {
    AuthResultCode result = AuthResultCode::kRejected;  ///< Outcome.
    uint32_t session_lifetime_ms = 0;  ///< New session lifetime in milliseconds.
    uint32_t new_epoch = 0;            ///< Epoch of the next keys; the client requires current epoch + 1.
};

/** @brief CLOSE payload: exactly one u16 reason. */
struct CloseMessage {
    CloseReason reason = CloseReason::kNormal;  ///< Close reason; unknown values are rejected.
};

/**
 * @brief Encodes an INTEGRITY_REPORT value.
 * @param[in]     in  Report.
 * @param[in,out] out Encoding is appended.
 * @retval OK                  Encoded.
 * @retval SG_INVALID_ARGUMENT build_id longer than kMaxBuildIdLength (nothing written), or the output fails
 *                             the self-check (e.g. unknown platform or flags).
 */
Status EncodeIntegrityReport(const IntegrityReport& in, Bytes* out);
/**
 * @brief Decodes an INTEGRITY_REPORT value.
 * @param[in]  in  Encoded report.
 * @param[out] out Decoded report.
 * @retval OK                Decoded.
 * @retval SG_PROTOCOL_ERROR report_version not 1, platform not 1..3, flags outside SG_INTEGRITY_KNOWN_FLAGS,
 *                           build_id too long, truncation or trailing bytes.
 */
Status DecodeIntegrityReport(ByteView in, IntegrityReport* out);

/**
 * @brief Encodes CLIENT_HELLO. Empty strings and has_* == false fields are omitted.
 * @param[in]     in  Message.
 * @param[in,out] out Encoding is appended.
 * @retval OK                  Encoded.
 * @retval SG_INVALID_ARGUMENT A string is too long or not a valid protocol string (nothing written),
 *                             enrollment_token_id is too long, the integrity report is invalid, or the
 *                             output fails the self-check (e.g. enrollment fields not matching auth_mode).
 * @note An over-long enrollment_token_id or an invalid integrity report is detected after the fixed part
 *       has been appended; that part is not removed.
 */
Status EncodeClientHello(const ClientHello& in, Bytes* out);
/**
 * @brief Decodes CLIENT_HELLO (*out is reset first).
 * @param[in]  in  Payload.
 * @param[out] out Decoded message.
 * @retval OK                Decoded.
 * @retval SG_PROTOCOL_ERROR Structural error, version_min 0 or above version_max, unknown key algorithm or
 *                           auth mode, invalid TLV value (empty or over-long string, invalid UTF-8,
 *                           REQUESTED_FEATURES not 8 bytes, invalid or over-long INTEGRITY_REPORT, empty or
 *                           over-long ENROLLMENT_TOKEN_ID, PUBLIC_KEY not a 65-byte 0x04 point), ENROLL
 *                           without both ENROLLMENT_TOKEN_ID and PUBLIC_KEY, or AUTHENTICATE with either.
 */
Status DecodeClientHello(ByteView in, ClientHello* out);

/**
 * @brief Encodes SERVER_HELLO with an empty extension section.
 * @param[in]     in  Message.
 * @param[in,out] out Encoding is appended.
 * @retval OK                  Encoded.
 * @retval SG_INVALID_ARGUMENT The output fails the self-check (zero version or TTL, unknown algorithm).
 */
Status EncodeServerHello(const ServerHello& in, Bytes* out);
/**
 * @brief Decodes SERVER_HELLO; extensions are validated and ignored.
 * @param[in]  in  Payload.
 * @param[out] out Decoded message.
 * @retval OK                Decoded.
 * @retval SG_PROTOCOL_ERROR Structural error, selected_version 0, challenge_ttl_ms 0 or unknown
 *                           server_proof_algorithm.
 */
Status DecodeServerHello(ByteView in, ServerHello* out);

/**
 * @brief Encodes CLIENT_PROOF (ENROLLMENT_PROOF TLV only when has_enrollment_proof).
 * @param[in]     in  Message.
 * @param[in,out] out Encoding is appended.
 * @retval OK                  Encoded.
 * @retval SG_INVALID_ARGUMENT The output fails the self-check (unknown signature algorithm).
 */
Status EncodeClientProof(const ClientProof& in, Bytes* out);
/**
 * @brief Decodes CLIENT_PROOF (*out is reset first).
 * @param[in]  in  Payload.
 * @param[out] out Decoded message.
 * @retval OK                Decoded.
 * @retval SG_PROTOCOL_ERROR Structural error, signature_algorithm not ECDSA P-256, signature not 64 bytes,
 *                           or ENROLLMENT_PROOF not 32 bytes.
 */
Status DecodeClientProof(ByteView in, ClientProof* out);

/**
 * @brief Encodes AUTH_RESULT.
 * @param[in]     in  Message.
 * @param[in,out] out Encoding is appended.
 * @retval OK                  Encoded.
 * @retval SG_INVALID_ARGUMENT has_server_signature does not match server_proof_algorithm or a non-OK result
 *                             carries session data or a proof algorithm (both detected before writing), or the
 *                             output fails the self-check (e.g. OK without policy or lifetime).
 */
Status EncodeAuthResult(const AuthResult& in, Bytes* out);
/**
 * @brief Decodes AUTH_RESULT (*out is reset first). The server signature is not verified here.
 * @param[in]  in  Payload.
 * @param[out] out Decoded message.
 * @retval OK                Decoded.
 * @retval SG_PROTOCOL_ERROR Structural error, unknown result / policy / algorithm, signature length not
 *                           matching the algorithm, OK without policy or lifetime, or a non-OK result with
 *                           any non-zero field or a proof algorithm.
 */
Status DecodeAuthResult(ByteView in, AuthResult* out);

/**
 * @brief Encodes a PING / PONG payload (no self-check).
 * @param[in]     in  Message.
 * @param[in,out] out Encoding is appended.
 * @retval OK Always.
 */
Status EncodePingPong(const PingPong& in, Bytes* out);
/**
 * @brief Decodes a PING / PONG payload.
 * @param[in]  in  Payload.
 * @param[out] out Decoded message.
 * @retval OK                Decoded.
 * @retval SG_PROTOCOL_ERROR Payload is not exactly 8 bytes.
 */
Status DecodePingPong(ByteView in, PingPong* out);

/**
 * @brief Encodes REAUTH_REQUEST (no self-check).
 * @param[in]     in  Message.
 * @param[in,out] out Encoding is appended.
 * @retval OK Always.
 */
Status EncodeReauthRequest(const ReauthRequest& in, Bytes* out);
/**
 * @brief Decodes REAUTH_REQUEST.
 * @param[in]  in  Payload.
 * @param[out] out Decoded message.
 * @retval OK                Decoded.
 * @retval SG_PROTOCOL_ERROR Payload is not exactly 32 bytes.
 */
Status DecodeReauthRequest(ByteView in, ReauthRequest* out);

/**
 * @brief Encodes REAUTH_CHALLENGE.
 * @param[in]     in  Message.
 * @param[in,out] out Encoding is appended.
 * @retval OK                  Encoded.
 * @retval SG_INVALID_ARGUMENT challenge_ttl_ms is 0 (self-check).
 */
Status EncodeReauthChallenge(const ReauthChallenge& in, Bytes* out);
/**
 * @brief Decodes REAUTH_CHALLENGE.
 * @param[in]  in  Payload.
 * @param[out] out Decoded message.
 * @retval OK                Decoded.
 * @retval SG_PROTOCOL_ERROR Payload is not exactly 68 bytes, or challenge_ttl_ms is 0.
 */
Status DecodeReauthChallenge(ByteView in, ReauthChallenge* out);

/**
 * @brief Encodes REAUTH_PROOF.
 * @param[in]     in  Message.
 * @param[in,out] out Encoding is appended.
 * @retval OK                  Encoded.
 * @retval SG_INVALID_ARGUMENT The output fails the self-check (unknown signature algorithm).
 */
Status EncodeReauthProof(const ReauthProof& in, Bytes* out);
/**
 * @brief Decodes REAUTH_PROOF.
 * @param[in]  in  Payload.
 * @param[out] out Decoded message.
 * @retval OK                Decoded.
 * @retval SG_PROTOCOL_ERROR Structural error, signature_algorithm not ECDSA P-256, or signature not 64 bytes.
 */
Status DecodeReauthProof(ByteView in, ReauthProof* out);

/**
 * @brief Encodes REAUTH_RESULT.
 * @param[in]     in  Message.
 * @param[in,out] out Encoding is appended.
 * @retval OK                  Encoded.
 * @retval SG_INVALID_ARGUMENT The output fails the self-check (see ReauthResult rules).
 */
Status EncodeReauthResult(const ReauthResult& in, Bytes* out);
/**
 * @brief Decodes REAUTH_RESULT.
 * @param[in]  in  Payload.
 * @param[out] out Decoded message.
 * @retval OK                Decoded.
 * @retval SG_PROTOCOL_ERROR Payload is not exactly 9 bytes, unknown result or kUnsupportedVersion, OK with a
 *                           zero lifetime, or a non-OK result with a non-zero lifetime or epoch.
 */
Status DecodeReauthResult(ByteView in, ReauthResult* out);

/**
 * @brief Encodes CLOSE.
 * @param[in]     in  Message.
 * @param[in,out] out Encoding is appended.
 * @retval OK                  Encoded.
 * @retval SG_INVALID_ARGUMENT Unknown reason (self-check).
 */
Status EncodeClose(const CloseMessage& in, Bytes* out);
/**
 * @brief Decodes CLOSE.
 * @param[in]  in  Payload.
 * @param[out] out Decoded message.
 * @retval OK                Decoded.
 * @retval SG_PROTOCOL_ERROR Payload is not exactly 2 bytes, or the reason is above CloseReason::kLimitExceeded.
 */
Status DecodeClose(ByteView in, CloseMessage* out);

}  // namespace sg::proto
