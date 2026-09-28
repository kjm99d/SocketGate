#include "crypto/key_store_factory.h"

#include <sockgate/config.h>

#include <vector>

namespace sg::client {
namespace {

#if defined(_WIN32) || defined(SOCKGATE_WITH_TPM2)
// Appends the store if the platform provides it; SG_NOT_SUPPORTED skips it.
Status AddIfSupported(Status created, std::unique_ptr<IKeyStore> store,
                      std::vector<std::unique_ptr<IKeyStore>>* stores)
{
    if (created == SG_NOT_SUPPORTED) return OkStatus();
    SG_TRY(created);
    stores->push_back(std::move(store));
    return OkStatus();
}
#endif

// Strongest first. AUTO never degrades to process memory.
Status CreateAuto(const std::string& path, std::unique_ptr<IKeyStore>* out)
{
    std::vector<std::unique_ptr<IKeyStore>> stores;
    std::unique_ptr<IKeyStore> store;
#if defined(_WIN32)
    Status st = CreateCngKeyStore(true, &store);
    SG_TRY(AddIfSupported(st, std::move(store), &stores));
    st = CreateCngKeyStore(false, &store);
    SG_TRY(AddIfSupported(st, std::move(store), &stores));
#else
#if defined(SOCKGATE_WITH_TPM2)
    const Status st = CreateTpm2KeyStore(path, &store);
    SG_TRY(AddIfSupported(st, std::move(store), &stores));
#endif
    SG_TRY(CreateFileKeyStore(path, &store));
    stores.push_back(std::move(store));
#endif
    if (stores.empty()) return SG_NOT_SUPPORTED;
#if defined(_WIN32)
    // CNG keys are per user, independent of key_store_path: so are their locators.
    (void)path;
    return CreateAutoKeyStore(std::move(stores), std::string(), out);
#else
    return CreateAutoKeyStore(std::move(stores), path, out);
#endif
}

}  // namespace

Status CreateKeyStore(uint32_t type, const std::string& path, std::unique_ptr<IKeyStore>* out)
{
    if (out == nullptr) return SG_INVALID_ARGUMENT;
    switch (type) {
    case SG_KEYSTORE_MEMORY:
        *out = CreateMemoryKeyStore();
        return OkStatus();
    case SG_KEYSTORE_AUTO:
        return CreateAuto(path, out);
    case SG_KEYSTORE_FILE:
        return CreateFileKeyStore(path, out);
    case SG_KEYSTORE_CNG_SOFTWARE:
    case SG_KEYSTORE_CNG_TPM:
#if defined(_WIN32)
        return CreateCngKeyStore(type == SG_KEYSTORE_CNG_TPM, out);
#else
        return SG_NOT_SUPPORTED;
#endif
    case SG_KEYSTORE_TPM2:
#if defined(SOCKGATE_WITH_TPM2)
        return CreateTpm2KeyStore(path, out);
#else
        return SG_NOT_SUPPORTED;
#endif
    default:
        return SG_INVALID_ARGUMENT;
    }
}

}  // namespace sg::client
