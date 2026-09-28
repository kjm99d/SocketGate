// SockGate wire protocol v1 constants (see docs/design/04-protocol-specification.md).
#pragma once

#include <array>
#include <cstddef>
#include <cstdint>

namespace sg::proto {

constexpr uint32_t kMagic = 0x53474154;  // "SGAT"
constexpr uint8_t kWireVersion = 1;       // frame layout version
constexpr uint16_t kProtocolVersion = 1;  // negotiated feature version
constexpr uint16_t kMinProtocolVersion = 1;
constexpr uint16_t kMaxProtocolVersion = 1;

constexpr size_t kHeaderSize = 48;
constexpr size_t kAuthTagSize = 16;
constexpr size_t kSessionIdSize = 16;
constexpr size_t kInstallationIdSize = 16;
constexpr size_t kNonceSize = 32;
constexpr size_t kChallengeSize = 32;
constexpr size_t kTokenIdSize = 16;

constexpr uint32_t kMaxHandshakePayload = 4096;
constexpr uint32_t kDefaultMaxPayload = 1u << 20;   // 1 MiB
constexpr uint32_t kAbsoluteMaxPayload = 16u << 20; // 16 MiB, cannot be raised by configuration

using SessionId = std::array<uint8_t, kSessionIdSize>;
using InstallationId = std::array<uint8_t, kInstallationIdSize>;
using Nonce = std::array<uint8_t, kNonceSize>;
using Challenge = std::array<uint8_t, kChallengeSize>;

enum class MessageType : uint8_t {
    kClientHello = 0x01,
    kServerHello = 0x02,
    kClientProof = 0x03,
    kAuthResult = 0x04,
    kData = 0x10,
    kPing = 0x11,
    kPong = 0x12,
    kReauthRequest = 0x20,
    kReauthChallenge = 0x21,
    kReauthProof = 0x22,
    kReauthResult = 0x23,
    kClose = 0x30,
};

bool IsKnownMessageType(uint8_t value) noexcept;
const char* MessageTypeName(MessageType type) noexcept;

// Frame flags.
constexpr uint16_t kFlagEncrypted = 1u << 0;
constexpr uint16_t kFlagResponse = 1u << 1;
constexpr uint16_t kFlagKeyPhase = 1u << 2;
constexpr uint16_t kKnownFlags = kFlagEncrypted | kFlagResponse | kFlagKeyPhase;

// Key / signature algorithms.
constexpr uint8_t kKeyAlgorithmEcdsaP256Sha256 = 1;
constexpr uint8_t kProofAlgorithmNone = 0;
constexpr uint8_t kProofAlgorithmEcdsaP256Sha256 = 1;

enum class AuthMode : uint8_t { kAuthenticate = 1, kEnroll = 2 };

enum class AuthResultCode : uint8_t {
    kOk = 0,
    kRejected = 1,
    kRetryLater = 2,
    kUnsupportedVersion = 3,
};

enum class SessionPolicy : uint8_t { kNone = 0, kNormal = 1, kRestricted = 2 };

enum class CloseReason : uint16_t {
    kNormal = 0,
    kProtocolError = 1,
    kAuthFailed = 2,
    kSessionExpired = 3,
    kServerShutdown = 4,
    kIdleTimeout = 5,
    kLimitExceeded = 6,
};

// CLIENT_HELLO TLV types.
namespace tlv {
constexpr uint16_t kProductId = 1;
constexpr uint16_t kProductVersion = 2;
constexpr uint16_t kLicenseId = 3;
constexpr uint16_t kRequestedFeatures = 4;
constexpr uint16_t kIntegrityReport = 5;
constexpr uint16_t kEnrollmentTokenId = 6;
constexpr uint16_t kPublicKey = 7;
// CLIENT_PROOF TLV types.
constexpr uint16_t kEnrollmentProof = 1;
}  // namespace tlv

constexpr size_t kMaxProductIdLength = 64;
constexpr size_t kMaxProductVersionLength = 32;
constexpr size_t kMaxLicenseIdLength = 128;
constexpr size_t kMaxIntegrityReportLength = 512;
constexpr size_t kMaxEnrollmentTokenIdLength = 512;
constexpr size_t kMaxBuildIdLength = 64;

// Domain separation labels (ASCII, no terminator on the wire).
constexpr char kTranscriptLabel[] = "SockGate/v1/transcript";
constexpr char kServerTranscriptLabel[] = "SockGate/v1/server-transcript";
constexpr char kReauthTranscriptLabel[] = "SockGate/v1/reauth";
constexpr char kClientProofContext[] = "SockGate/v1/client-proof";
constexpr char kServerProofContext[] = "SockGate/v1/server-proof";
constexpr char kReauthProofContext[] = "SockGate/v1/reauth-proof";
constexpr char kEnrollKeyContext[] = "SockGate/v1/enroll-key";
constexpr char kEnrollProofContext[] = "SockGate/v1/enroll-proof";
constexpr char kInstallationIdContext[] = "SockGate/v1/iid";
constexpr char kKeyExporterLabel[] = "EXPORTER-SockGate-v1-keys";
constexpr char kC2SKeyInfo[] = "SockGate/v1 c2s";
constexpr char kS2CKeyInfo[] = "SockGate/v1 s2c";

}  // namespace sg::proto
