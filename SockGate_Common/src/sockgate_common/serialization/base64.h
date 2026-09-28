// Strict base64url (RFC 4648 §5) without padding, used for token strings.
#pragma once

#include "sockgate_common/core/bytes.h"
#include "sockgate_common/core/status.h"

#include <string>

namespace sg::ser {

std::string Base64UrlEncode(ByteView data);

// Rejects padding, whitespace, characters outside the url-safe alphabet and
// non-canonical trailing bits. Output is appended to *out.
Status Base64UrlDecode(const std::string& text, SecureBytes* out);

}  // namespace sg::ser
