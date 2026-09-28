#pragma once
/**
 * @file
 * @brief Creates the key store selected by SG_ClientConfig.key_store_type.
 */

#include "crypto/key_store.h"

#include <memory>
#include <string>

namespace sg::client {

/**
 * @brief Creates the key store for @p type.
 *
 * type: SG_KEYSTORE_*. `path` is the FILE store directory ("" = default); it is also the TPM2 blob directory and,
 * on Linux, the AUTO key and locator directory.
 *
 * - SG_KEYSTORE_MEMORY: CreateMemoryKeyStore().
 * - SG_KEYSTORE_AUTO: Windows: CNG TPM, then CNG Software KSP; a provider that cannot be opened
 *   (SG_NOT_SUPPORTED) is left out, and locators live in the per-user default directory (@p path is ignored, as
 *   CNG keys are per user). Linux: TPM2 (builds with SOCKGATE_WITH_TPM2), then FILE, with keys and locators in
 *   @p path. Never includes process memory. See CreateAutoKeyStore().
 * - SG_KEYSTORE_FILE: CreateFileKeyStore().
 * - SG_KEYSTORE_CNG_SOFTWARE, SG_KEYSTORE_CNG_TPM: CreateCngKeyStore() (Windows only).
 * - SG_KEYSTORE_TPM2: CreateTpm2KeyStore() (builds with SOCKGATE_WITH_TPM2 only).
 *
 * Errors of the Create*KeyStore() functions are passed through.
 *
 * @param[in]  type SG_KEYSTORE_* value.
 * @param[in]  path Key store directory ("" = per-user default).
 * @param[out] out  Receives the store.
 * @retval SG_OK               Store created.
 * @retval SG_INVALID_ARGUMENT @p out is nullptr or @p type is unknown.
 * @retval SG_NOT_SUPPORTED    The type is not available on this platform or build (AUTO: no store available).
 * @retval SG_NOT_FOUND        (Windows) A key or locator directory cannot be created.
 * @retval SG_KEYSTORE_ERROR   The key directory cannot be prepared.
 */
Status CreateKeyStore(uint32_t type, const std::string& path, std::unique_ptr<IKeyStore>* out);

}  // namespace sg::client
