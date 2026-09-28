// Enrollment token format (docs/design/05-handshake-sequence.md §2).
//
//   claims    = u8 version(=1) || vec16 product_id || vec16 license_id
//               || u64 issued_at_ms || u64 expires_at_ms
//   token_pub = token_id(16) || claims                 (sent in CLIENT_HELLO)
//   K_tok     = HMAC-SHA256(server_token_key, "SockGate/v1/enroll-key" || 0x00 || token_pub)
//   token     = base64url(token_pub || K_tok)          (handed to the application)
//
// K_tok is never transmitted; the client proves possession with a MAC over
// the channel-bound transcript.
#pragma once

#include "sockgate_common/core/bytes.h"
#include "sockgate_common/core/status.h"
#include "sockgate_common/crypto/crypto.h"
#include "sockgate_common/protocol/constants.h"

#include <array>
#include <string>

namespace sg::proto {

using TokenId = std::array<uint8_t, kTokenIdSize>;

// Longest validity a built-in enrollment token may have. Enforced when
// issuing and again when the token is redeemed (a token minted elsewhere
// with the server's key cannot outlive it).
constexpr uint64_t kMaxEnrollmentTokenLifetimeMs = 30ull * 24 * 3600 * 1000;

struct EnrollmentClaims {
    TokenId token_id{};
    std::string product_id;  // required, 1..64
    std::string license_id;  // optional, 0..128
    uint64_t issued_at_ms = 0;
    uint64_t expires_at_ms = 0;
};

Status EncodeTokenPublic(const EnrollmentClaims& claims, Bytes* token_pub);
Status DecodeTokenPublic(ByteView token_pub, EnrollmentClaims* claims);

// Derives K_tok from the server secret and the public part.
Status DeriveEnrollmentKey(ByteView server_token_key, ByteView token_pub, crypto::Sha256Digest* k_tok);

// Server side: builds the token string handed to the application.
Status BuildEnrollmentToken(ByteView server_token_key, const EnrollmentClaims& claims, std::string* token);

// Client side: splits a token string into token_pub and K_tok.
Status ParseEnrollmentToken(const std::string& token, Bytes* token_pub, crypto::Sha256Digest* k_tok);

}  // namespace sg::proto
