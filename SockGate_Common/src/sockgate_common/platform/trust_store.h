// Loads the operating system's trusted root certificates into an OpenSSL store.
#pragma once

#include "sockgate_common/core/status.h"

#include <openssl/x509.h>

namespace sg::platform {

// Windows: certificates of the current user's/machine's "ROOT" system store.
// Linux:   OpenSSL default verify paths (distribution CA bundle).
Status AddSystemTrustAnchors(X509_STORE* store);

}  // namespace sg::platform
