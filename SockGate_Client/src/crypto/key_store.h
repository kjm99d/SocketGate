// Installation key storage abstraction (IKeyStore).
//
// Core code refers to keys only by name and asks the store to sign; it never
// sees private key bytes. Implementations:
//   MemoryKeyStore   process memory (tests, ephemeral identities)
//   FileKeyStore     PKCS#8 file (0600 on Linux, DPAPI-wrapped on Windows)
//   CngKeyStore      Windows CNG, TPM (Platform Crypto Provider) or software KSP
//   Tpm2KeyStore     Linux TPM2 via tpm2-tss (optional build)
#pragma once

#include "sockgate_common/core/bytes.h"
#include "sockgate_common/core/status.h"
#include "sockgate_common/crypto/crypto.h"
#include "sockgate_common/protocol/constants.h"

#include <memory>
#include <string>

namespace sg::client {

enum class KeyStoreKind : uint32_t {
    kMemory = 1,
    kFile = 2,
    kCngSoftware = 3,
    kCngTpm = 4,
    kTpm2 = 5,
};

const char* KeyStoreKindName(KeyStoreKind kind) noexcept;

class IKeyStore {
public:
    virtual ~IKeyStore() = default;

    virtual KeyStoreKind Kind() const noexcept = 0;
    // True when the private key cannot leave a hardware boundary (TPM).
    virtual bool HardwareBacked() const noexcept = 0;

    // Creates a new ECDSA P-256 key. SG_ALREADY_EXISTS if the name is taken
    // (creation is exclusive, so concurrent creators cannot both succeed).
    virtual Status GenerateKeyPair(const std::string& name) = 0;

    // SG_NOT_FOUND if the key does not exist.
    virtual Status GetPublicKey(const std::string& name, crypto::P256PublicKey* out) = 0;

    // ECDSA-P256-SHA256 over `message` (the store hashes), P1363 output.
    virtual Status Sign(const std::string& name, ByteView message, crypto::P256Signature* out) = 0;

    virtual Status DeleteKey(const std::string& name) = 0;
};

// Key names are restricted to [A-Za-z0-9._-], 1..128 characters, so they can
// be used safely as file names and CNG key names.
Status ValidateKeyName(const std::string& name);

struct IdentityInfo {
    crypto::P256PublicKey public_key{};
    proto::InstallationId installation_id{};
    KeyStoreKind kind = KeyStoreKind::kMemory;
    bool hardware_backed = false;
    bool created = false;  // true if EnsureIdentity generated a new key
};

// Loads the named identity, creating it when absent (tolerates a concurrent
// creator winning the race). The installation id is derived from the key.
Status EnsureIdentity(IKeyStore& store, const std::string& name, IdentityInfo* out);
Status GetIdentity(IKeyStore& store, const std::string& name, IdentityInfo* out);

// In-memory key store (no persistence).
std::unique_ptr<IKeyStore> CreateMemoryKeyStore();

}  // namespace sg::client
