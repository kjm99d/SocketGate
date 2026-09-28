#pragma once
/**
 * @file
 * @brief Strict base64url (RFC 4648 §5) without padding, used for token strings.
 */

#include "sockgate_common/core/bytes.h"
#include "sockgate_common/core/status.h"

#include <string>

namespace sg::ser {

/**
 * @brief Encodes bytes as base64url without padding.
 * @param[in] data Bytes to encode.
 * @return The encoded text (alphabet A-Z a-z 0-9 - _, no '=').
 */
std::string Base64UrlEncode(ByteView data);

/**
 * @brief Decodes strict unpadded base64url.
 *
 * Rejects padding, whitespace, characters outside the url-safe alphabet and non-canonical trailing bits. Output
 * is appended to *out. The decoder's internal bit accumulator is wiped before returning.
 *
 * @param[in]     text Encoded text.
 * @param[in,out] out  Decoded bytes are appended here (SecureBytes: wiped on release).
 * @retval SG_OK               Success.
 * @retval SG_INVALID_ARGUMENT @p out is null, the length is impossible (length % 4 == 1), a character is invalid,
 *                             or the trailing bits are non-zero. Bytes decoded before the error may already
 *                             have been appended to @p out.
 */
Status Base64UrlDecode(const std::string& text, SecureBytes* out);

}  // namespace sg::ser
