#include "sockgate_common/platform/trust_store.h"

#include <windows.h>
#include <wincrypt.h>

#include <openssl/err.h>

namespace sg::platform {

Status AddSystemTrustAnchors(X509_STORE* store)
{
    if (store == nullptr) return SG_INVALID_ARGUMENT;
    HCERTSTORE system_store = CertOpenSystemStoreW(0, L"ROOT");
    if (system_store == nullptr) return SG_CERTIFICATE_ERROR;

    int added = 0;
    PCCERT_CONTEXT ctx = nullptr;
    while ((ctx = CertEnumCertificatesInStore(system_store, ctx)) != nullptr) {
        if (ctx->dwCertEncodingType != X509_ASN_ENCODING && (ctx->dwCertEncodingType & X509_ASN_ENCODING) == 0) {
            continue;
        }
        const unsigned char* p = ctx->pbCertEncoded;
        X509* cert = d2i_X509(nullptr, &p, static_cast<long>(ctx->cbCertEncoded));
        if (cert == nullptr) continue;
        // Duplicates are reported as errors by some OpenSSL versions; ignore them.
        if (X509_STORE_add_cert(store, cert) == 1) ++added;
        X509_free(cert);
    }
    CertCloseStore(system_store, 0);
    ERR_clear_error();
    return added > 0 ? OkStatus() : Status(SG_CERTIFICATE_ERROR);
}

}  // namespace sg::platform
