#pragma once
/**
 * @file
 * @brief Loads the operating system's trusted root certificates into an OpenSSL store.
 */

#include "sockgate_common/core/status.h"

#include <openssl/x509.h>

namespace sg::platform {

/**
 * @brief Adds the operating system's trusted root certificates to @p store.
 *
 * - Windows: certificates of the current user's/machine's "ROOT" system store. Certificates that fail to parse
 *   or to be added (e.g. duplicates) are skipped.
 * - Linux: OpenSSL default verify paths (distribution CA bundle). OpenSSL registers the default file and
 *   directory lookups and ignores failures to load them, so a missing or empty CA bundle is not detected here.
 *
 * OpenSSL errors raised while loading are cleared from the calling thread's error queue.
 *
 * @warning On Linux SG_OK does not mean that any trust anchor was added; with no system CA bundle, certificate
 *          verification against @p store fails later.
 *
 * @param[in,out] store OpenSSL store to extend (not owned).
 * @retval SG_OK                Windows: at least one certificate was added. Linux: the default lookups were
 *                              registered (no anchor count is checked).
 * @retval SG_INVALID_ARGUMENT  @p store is null.
 * @retval SG_CERTIFICATE_ERROR Windows: the system store could not be opened or no certificate was added.
 *                              Linux: a default lookup could not be registered.
 */
Status AddSystemTrustAnchors(X509_STORE* store);

}  // namespace sg::platform
