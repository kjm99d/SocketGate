#include "crypto/key_store_factory.h"

#include <sockgate/config.h>

namespace sg::client {

Status CreateKeyStore(uint32_t type, const std::string& path, std::unique_ptr<IKeyStore>* out)
{
    (void)path;
    if (out == nullptr) return SG_INVALID_ARGUMENT;
    switch (type) {
    case SG_KEYSTORE_MEMORY:
        *out = CreateMemoryKeyStore();
        return OkStatus();
    case SG_KEYSTORE_AUTO:
    case SG_KEYSTORE_FILE:
    case SG_KEYSTORE_CNG_SOFTWARE:
    case SG_KEYSTORE_CNG_TPM:
    case SG_KEYSTORE_TPM2:
        // Persistent / platform-backed stores are provided by the platform
        // security layer; AUTO never silently degrades to process memory.
        return SG_NOT_SUPPORTED;
    default:
        return SG_INVALID_ARGUMENT;
    }
}

}  // namespace sg::client
