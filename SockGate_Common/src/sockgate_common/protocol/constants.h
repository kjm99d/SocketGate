#pragma once
/**
 * @file
 * @brief SockGate wire protocol v1 constants (see docs/design/04-protocol-specification.md).
 *
 * All multi-byte integers on the wire are big endian. Sizes and length limits are in bytes, times in
 * milliseconds. These constants are internal: the public C headers do not expose them.
 */

#include <array>
#include <cstddef>
#include <cstdint>

/** @brief SockGate wire protocol: constants, frame codec, message codecs, transcripts and frame protection. */
namespace sg::proto {

constexpr uint32_t kMagic = 0x53474154;  ///< Frame header magic, the ASCII bytes "SGAT" (header offset 0).
constexpr uint8_t kWireVersion = 1;       ///< Frame layout version (header `version` field); always 1 in v1.
constexpr uint16_t kProtocolVersion = 1;  ///< Negotiated feature version (CLIENT_HELLO min/max, SERVER_HELLO).
constexpr uint16_t kMinProtocolVersion = 1;  ///< Lowest protocol feature version this build supports.
constexpr uint16_t kMaxProtocolVersion = 1;  ///< Highest protocol feature version this build supports.

constexpr size_t kHeaderSize = 48;          ///< Fixed frame header size in bytes.
constexpr size_t kAuthTagSize = 16;         ///< AES-256-GCM tag size in bytes (`auth_length` is 0 or this).
constexpr size_t kSessionIdSize = 16;       ///< Session id size in bytes (assigned by the server in SERVER_HELLO).
constexpr size_t kInstallationIdSize = 16;  ///< Installation id size in bytes.
constexpr size_t kNonceSize = 32;           ///< Client / server nonce size in bytes.
constexpr size_t kChallengeSize = 32;       ///< Server challenge size in bytes.
constexpr size_t kTokenIdSize = 16;         ///< Enrollment token id size in bytes.

/** @brief Payload limit in bytes for every frame before authentication and for non-DATA frames after it. */
constexpr uint32_t kMaxHandshakePayload = 4096;
constexpr uint32_t kDefaultMaxPayload = 1u << 20;   ///< Default DATA payload limit: 1 MiB (configurable).
constexpr uint32_t kAbsoluteMaxPayload = 16u << 20; ///< 16 MiB payload bound; cannot be raised by configuration.

using SessionId = std::array<uint8_t, kSessionIdSize>;            ///< 16-byte session id (all zero before assignment).
using InstallationId = std::array<uint8_t, kInstallationIdSize>;  ///< 16-byte installation id.
using Nonce = std::array<uint8_t, kNonceSize>;                    ///< 32-byte nonce.
using Challenge = std::array<uint8_t, kChallengeSize>;            ///< 32-byte server challenge.

/**
 * @brief Frame header `type` values.
 *
 * Direction and allowed receiver phase are enforced by CheckHeaderForState() (rules.h). Any other value is a
 * protocol error (IsKnownMessageType()).
 */
enum class MessageType : uint8_t {
    kClientHello = 0x01,       ///< CLIENT_HELLO, client to server; server phase kAwaitClientHello.
    kServerHello = 0x02,       ///< SERVER_HELLO, server to client; carries the new session id in the header.
    kClientProof = 0x03,       ///< CLIENT_PROOF, client to server; signature over TH1.
    /// AUTH_RESULT, server to client; also accepted in kAwaitServerHello, for UNSUPPORTED_VERSION only.
    kAuthResult = 0x04,
    kData = 0x10,              ///< DATA, both directions, authenticated only; the only type with request ids.
    kPing = 0x11,              ///< PING, both directions, authenticated only; payload u64 opaque.
    kPong = 0x12,              ///< PONG, both directions, authenticated only; payload u64 opaque.
    kReauthRequest = 0x20,     ///< REAUTH_REQUEST, client to server; server phase kActive.
    kReauthChallenge = 0x21,   ///< REAUTH_CHALLENGE, server to client; client phase kRefreshing.
    kReauthProof = 0x22,       ///< REAUTH_PROOF, client to server; server phase kRefreshing.
    kReauthResult = 0x23,      ///< REAUTH_RESULT, server to client; client phase kRefreshing.
    kClose = 0x30,             ///< CLOSE, both directions, every phase except kClosed.
};

/**
 * @brief Tells whether @p value is one of the MessageType values.
 * @param[in] value Raw header `type` byte.
 * @return true for a defined message type, false otherwise.
 */
bool IsKnownMessageType(uint8_t value) noexcept;
/**
 * @brief Returns the protocol name of a message type ("CLIENT_HELLO", "DATA", ...).
 * @param[in] type Message type.
 * @return Static string; "UNKNOWN" for an undefined value. Never nullptr.
 */
const char* MessageTypeName(MessageType type) noexcept;

// Frame flags.
/** @brief Payload is encrypted with the application-layer AEAD (bit 0). Allowed only after authentication. */
constexpr uint16_t kFlagEncrypted = 1u << 0;
/** @brief `request_id` is the id of the peer's request this frame answers (bit 1). DATA only, with request_id != 0. */
constexpr uint16_t kFlagResponse = 1u << 1;
/**
 * @brief KEY_PHASE (bit 2): `epoch & 1` of the key that protects the frame.
 *
 * Meaningful only after authentication; it is part of the AAD (header), so changing it breaks the tag.
 */
constexpr uint16_t kFlagKeyPhase = 1u << 2;
/** @brief All defined flag bits; any other bit (3-15) is reserved and must be 0. Frames before authentication use 0. */
constexpr uint16_t kKnownFlags = kFlagEncrypted | kFlagResponse | kFlagKeyPhase;

// Key / signature algorithms.
/** @brief ECDSA P-256 with SHA-256: CLIENT_HELLO `key_algorithm` and the proof `signature_algorithm`. */
constexpr uint8_t kKeyAlgorithmEcdsaP256Sha256 = 1;
constexpr uint8_t kProofAlgorithmNone = 0;             ///< `server_proof_algorithm`: no server proof.
constexpr uint8_t kProofAlgorithmEcdsaP256Sha256 = 1;  ///< `server_proof_algorithm`: ECDSA P-256 / SHA-256 over TH2.

/**
 * @brief CLIENT_HELLO `auth_mode`.
 *
 * kAuthenticate forbids the ENROLLMENT_TOKEN_ID and PUBLIC_KEY TLVs; kEnroll requires both.
 */
enum class AuthMode : uint8_t { kAuthenticate = 1, /**< Registered installation. */ kEnroll = 2 /**< Enrollment. */ };

/** @brief `result` of AUTH_RESULT and REAUTH_RESULT. */
enum class AuthResultCode : uint8_t {
    kOk = 0,                  ///< Authenticated; the message carries session data.
    kRejected = 1,            ///< Rejected; all other fields are 0.
    kRetryLater = 2,          ///< Try again later; all other fields are 0.
    kUnsupportedVersion = 3,  ///< No common protocol version (AUTH_RESULT only; invalid in REAUTH_RESULT).
};

/**
 * @brief Session policy decided by the server (AUTH_RESULT `session_policy`; mirrors SG_SESSION_POLICY_*).
 *
 * - kNone (0): no session; required in every non-OK AUTH_RESULT and invalid with OK.
 * - kNormal (1): normal session.
 * - kRestricted (2): restricted session.
 */
enum class SessionPolicy : uint8_t { kNone = 0, kNormal = 1, kRestricted = 2 };

/** @brief CLOSE `reason` (u16). Values above kLimitExceeded are a protocol error. */
enum class CloseReason : uint16_t {
    kNormal = 0,          ///< Orderly close.
    kProtocolError = 1,   ///< Protocol violation.
    kAuthFailed = 2,      ///< Authentication failed.
    kSessionExpired = 3,  ///< Session lifetime ended.
    kServerShutdown = 4,  ///< Server is shutting down.
    kIdleTimeout = 5,     ///< Idle timeout.
    kLimitExceeded = 6,   ///< A limit was exceeded.
};

/** @brief TLV extension type codes, scoped per message (CLIENT_HELLO and CLIENT_PROOF reuse small numbers). */
namespace tlv {
// CLIENT_HELLO TLV types.
constexpr uint16_t kProductId = 1;          ///< PRODUCT_ID: UTF-8, 1..kMaxProductIdLength bytes.
constexpr uint16_t kProductVersion = 2;     ///< PRODUCT_VERSION: UTF-8, 1..kMaxProductVersionLength bytes.
constexpr uint16_t kLicenseId = 3;          ///< LICENSE_ID: UTF-8, 1..kMaxLicenseIdLength bytes.
constexpr uint16_t kRequestedFeatures = 4;  ///< REQUESTED_FEATURES: u64 bitmask (exactly 8 bytes).
constexpr uint16_t kIntegrityReport = 5;    ///< INTEGRITY_REPORT: IntegrityReport, <= kMaxIntegrityReportLength bytes.
/// ENROLLMENT_TOKEN_ID: public part of the enrollment token (token_pub), 1..kMaxEnrollmentTokenIdLength; ENROLL only.
constexpr uint16_t kEnrollmentTokenId = 6;
constexpr uint16_t kPublicKey = 7;          ///< PUBLIC_KEY: SEC1 uncompressed P-256 point (65 bytes); ENROLL only.
// CLIENT_PROOF TLV types.
constexpr uint16_t kEnrollmentProof = 1;    ///< ENROLLMENT_PROOF: HMAC-SHA256 over TH1 (32 bytes).
}  // namespace tlv

constexpr size_t kMaxProductIdLength = 64;          ///< PRODUCT_ID / claims product_id limit in bytes.
constexpr size_t kMaxProductVersionLength = 32;     ///< PRODUCT_VERSION limit in bytes.
constexpr size_t kMaxLicenseIdLength = 128;         ///< LICENSE_ID / claims license_id limit in bytes.
constexpr size_t kMaxIntegrityReportLength = 512;   ///< Encoded INTEGRITY_REPORT TLV value limit in bytes.
constexpr size_t kMaxEnrollmentTokenIdLength = 512; ///< ENROLLMENT_TOKEN_ID (token_pub) limit in bytes.
constexpr size_t kMaxBuildIdLength = 64;            ///< IntegrityReport build_id limit in bytes.

/**
 * @name Domain separation labels
 * ASCII, no terminator on the wire.
 * @{
 */
constexpr char kTranscriptLabel[] = "SockGate/v1/transcript";               ///< Prefix of TH1.
constexpr char kServerTranscriptLabel[] = "SockGate/v1/server-transcript";  ///< Prefix of TH2.
constexpr char kReauthTranscriptLabel[] = "SockGate/v1/reauth";             ///< Prefix of THr.
constexpr char kClientProofContext[] = "SockGate/v1/client-proof";          ///< CLIENT_PROOF signed-data context (TH1).
constexpr char kServerProofContext[] = "SockGate/v1/server-proof";          ///< Server proof signed-data context (TH2).
constexpr char kReauthProofContext[] = "SockGate/v1/reauth-proof";          ///< REAUTH_PROOF signed-data context (THr).
constexpr char kEnrollKeyContext[] = "SockGate/v1/enroll-key";              ///< HMAC context deriving K_tok.
constexpr char kEnrollProofContext[] = "SockGate/v1/enroll-proof";          ///< HMAC context of ENROLLMENT_PROOF.
constexpr char kInstallationIdContext[] = "SockGate/v1/iid";                ///< Hash prefix of the installation id.
/// TLS exporter label for the 32-byte channel key material `km` (context TH1, or THr on reauthentication).
constexpr char kKeyExporterLabel[] = "EXPORTER-SockGate-v1-keys";
constexpr char kC2SKeyInfo[] = "SockGate/v1 c2s";  ///< HKDF info prefix (then u32 epoch) of the client-to-server key.
constexpr char kS2CKeyInfo[] = "SockGate/v1 s2c";  ///< HKDF info prefix (then u32 epoch) of the server-to-client key.
/** @} */

}  // namespace sg::proto
