#include "sockgate_common/platform/trust_store.h"

#include <openssl/err.h>

namespace sg::platform {

Status AddSystemTrustAnchors(X509_STORE* store)
{
    if (store == nullptr) return SG_INVALID_ARGUMENT;
    const int rc = X509_STORE_set_default_paths(store);
    ERR_clear_error();
    return rc == 1 ? OkStatus() : Status(SG_CERTIFICATE_ERROR);
}

}  // namespace sg::platform
