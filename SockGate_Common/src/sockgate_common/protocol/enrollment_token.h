#pragma once
/**
 * @file
 * @brief Enrollment token format (docs/design/05-handshake-sequence.md §2).
 *
 * @code{.unparsed}
 *   claims    = u8 version(=1) || vec16 product_id || vec16 license_id
 *               || u64 issued_at_ms || u64 expires_at_ms
 *   token_pub = token_id(16) || claims                 (sent in CLIENT_HELLO)
 *   K_tok     = HMAC-SHA256(server_token_key, "SockGate/v1/enroll-key" || 0x00 || token_pub)
 *   token     = base64url(token_pub || K_tok)          (handed to the application)
 * @endcode
 *
 * K_tok is never transmitted; the client proves possession with a MAC over
 * the channel-bound transcript (ComputeEnrollmentProof() over TH1).
 *
 * Integers are big endian; base64url is RFC 4648 §5 without padding.
 */

#include "sockgate_common/core/bytes.h"
#include "sockgate_common/core/status.h"
#include "sockgate_common/crypto/crypto.h"
#include "sockgate_common/protocol/constants.h"

#include <array>
#include <string>

namespace sg::proto {

using TokenId = std::array<uint8_t, kTokenIdSize>;  ///< 16-byte enrollment token id.

/**
 * @brief Longest validity (30 days, in milliseconds) a built-in enrollment token may have.
 *
 * Enforced when
 * issuing and again when the token is redeemed (a token minted elsewhere
 * with the server's key cannot outlive it). The server does both; the functions in this header do not.
 */
constexpr uint64_t kMaxEnrollmentTokenLifetimeMs = 30ull * 24 * 3600 * 1000;

/** @brief Decoded enrollment token claims (plus the token id). */
struct EnrollmentClaims {
    TokenId token_id{};         ///< Token id (first 16 bytes of token_pub).
    std::string product_id;  ///< Required, 1..64 bytes (kMaxProductIdLength), strict UTF-8 without controls.
    std::string license_id;  ///< Optional, 0..128 bytes (kMaxLicenseIdLength), strict UTF-8 without controls.
    uint64_t issued_at_ms = 0;  ///< Issue time, Unix epoch milliseconds.
    uint64_t expires_at_ms = 0; ///< Expiry, Unix epoch milliseconds; must be greater than issued_at_ms.
};

/**
 * @brief Serialises token_pub = token_id || claims.
 * @param[in]     claims    Claims to encode.
 * @param[in,out] token_pub The encoding is appended.
 * @retval OK                  Encoded.
 * @retval SG_INVALID_ARGUMENT @p token_pub is nullptr, product_id is empty or too long, license_id is too
 *                             long, a string is not a valid protocol string, or expires_at_ms <= issued_at_ms.
 * @note Does not check kMaxEnrollmentTokenLifetimeMs.
 */
Status EncodeTokenPublic(const EnrollmentClaims& claims, Bytes* token_pub);
/**
 * @brief Parses token_pub strictly (as received in the ENROLLMENT_TOKEN_ID TLV).
 * @param[in]  token_pub Encoded token_pub; at most kMaxEnrollmentTokenIdLength bytes.
 * @param[out] claims    Receives the claims; may be partially written on failure.
 * @retval OK                Parsed.
 * @retval SG_PROTOCOL_ERROR @p claims is nullptr, input too long or truncated, claims version not 1, a string
 *                           of invalid length or content, trailing bytes, or expires_at_ms <= issued_at_ms.
 * @note Structural only: does not verify K_tok, expiry or the lifetime limit.
 */
Status DecodeTokenPublic(ByteView token_pub, EnrollmentClaims* claims);

/**
 * @brief Derives K_tok from the server secret and the public part.
 *
 * K_tok = HMAC-SHA256(server_token_key, "SockGate/v1/enroll-key" || 0x00 || token_pub)
 *
 * @param[in]  server_token_key Server token secret; at least 32 bytes.
 * @param[in]  token_pub        Encoded token_pub.
 * @param[out] k_tok            Receives K_tok.
 * @retval OK                  Derived.
 * @retval SG_INVALID_ARGUMENT @p server_token_key is shorter than 32 bytes, or @p k_tok is nullptr.
 * @retval SG_CRYPTO_ERROR     MAC failure.
 * @warning K_tok is a secret; the caller wipes it after use.
 */
Status DeriveEnrollmentKey(ByteView server_token_key, ByteView token_pub, crypto::Sha256Digest* k_tok);

/**
 * @brief Server side: builds the token string handed to the application.
 *
 * token = base64url(token_pub || K_tok). The intermediate K_tok is wiped.
 *
 * @param[in]  server_token_key Server token secret; at least 32 bytes.
 * @param[in]  claims           Claims (validated as by EncodeTokenPublic()).
 * @param[out] token            Receives the token; its previous contents are wiped first.
 * @retval OK                  Token built.
 * @retval SG_INVALID_ARGUMENT @p token is nullptr, invalid claims, or a key shorter than 32 bytes.
 * @retval SG_CRYPTO_ERROR     MAC failure.
 * @warning The token contains K_tok: treat it as a secret.
 * @note Does not check kMaxEnrollmentTokenLifetimeMs (the caller does).
 */
Status BuildEnrollmentToken(ByteView server_token_key, const EnrollmentClaims& claims, std::string* token);

/**
 * @brief Client side: splits a token string into token_pub and K_tok.
 *
 * Decodes strict base64url; the last 32 bytes are K_tok and the rest must parse as token_pub
 * (DecodeTokenPublic()).
 *
 * @param[in]  token     Token string, 1..1024 characters.
 * @param[out] token_pub Receives token_pub (previous contents replaced).
 * @param[out] k_tok     Receives K_tok.
 * @retval OK                  Parsed.
 * @retval SG_INVALID_ARGUMENT Null output, empty or over-long token, invalid base64url, too short, or
 *                             token_pub does not parse.
 * @warning K_tok is a secret; the caller wipes it after use. Expiry is not checked here.
 */
Status ParseEnrollmentToken(const std::string& token, Bytes* token_pub, crypto::Sha256Digest* k_tok);

}  // namespace sg::proto
