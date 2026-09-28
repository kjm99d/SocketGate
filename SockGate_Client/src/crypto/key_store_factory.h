// Creates the key store selected by SG_ClientConfig.key_store_type.
#pragma once

#include "crypto/key_store.h"

#include <memory>
#include <string>

namespace sg::client {

// type: SG_KEYSTORE_*. `path` is the FILE store directory ("" = default).
Status CreateKeyStore(uint32_t type, const std::string& path, std::unique_ptr<IKeyStore>* out);

}  // namespace sg::client
