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
#include <vector>

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
    // Like DeleteKey, but also forgets an identity whose store is currently
    // unavailable (AUTO); a key in that store may survive. Explicit reset only.
    virtual Status ForceDeleteKey(const std::string& name) { return DeleteKey(name); }

    // Public key and the store actually holding it, from one lookup (differs
    // from Kind() only for AUTO).
    virtual Status Describe(const std::string& name, crypto::P256PublicKey* public_key, KeyStoreKind* kind,
                            bool* hardware_backed);
};

// Key names are restricted to [A-Za-z0-9._-], 1..128 characters, so they can
// be used safely as file names and CNG key names; Windows device names (CON,
// NUL, COM1, ...) are refused on every platform. Names are shared by all
// applications of a user: use a reverse-DNS style name ("com.example.app").
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

// FILE key store in `directory` ("" = per-user default, see platform/key_file.h).
// One file per key; DPAPI-protected on Windows, owner-only (0600) on Linux.
Status CreateFileKeyStore(const std::string& directory, std::unique_ptr<IKeyStore>* out);

// AUTO: keys are looked up in every store; new keys are created in the first
// (strongest) store that supports key creation. A locator file per identity
// in `locator_directory` ("" = per-user default) records the store that
// created it, and only that store is asked afterwards:
//   store not available (TPM provider cannot be opened) -> SG_KEYSTORE_ERROR
//   store available but the key is gone (TPM cleared)    -> SG_IDENTITY_LOST
// Neither case creates a replacement identity. DeleteKey refuses while the
// recorded store is unavailable; ForceDeleteKey forgets the identity anyway.
// Stores never degrade to process memory.
Status CreateAutoKeyStore(std::vector<std::unique_ptr<IKeyStore>> stores, const std::string& locator_directory,
                          std::unique_ptr<IKeyStore>* out);

#ifdef _WIN32
// Windows CNG: Microsoft Platform Crypto Provider (TPM) when `tpm`, else the
// Microsoft Software KSP (non-exportable per-user keys). SG_NOT_SUPPORTED if
// the provider is unavailable. GenerateKeyPair returns SG_NOT_SUPPORTED only
// for definite answers (no TPM 2.0, algorithm unsupported); transient
// failures are SG_KEYSTORE_ERROR. Existing keys are always looked up, and
// lookup failures are errors, never "key absent".
Status CreateCngKeyStore(bool tpm, std::unique_ptr<IKeyStore>* out);
#endif

#ifdef SOCKGATE_WITH_TPM2
// Linux TPM2 (tpm2-tss ESAPI): keys never leave the TPM; TPM-wrapped key
// blobs are kept in `directory` (owner-only, like FILE keys). The TPM is
// reached through /dev/tpmrm0 or SOCKGATE_TPM2_TCTI (device/tabrmd/swtpm/
// mssim only; simulators are for testing). GenerateKeyPair returns
// SG_NOT_SUPPORTED only for definite answers (no TPM access, owner auth set,
// algorithm unsupported); existing keys are always found.
Status CreateTpm2KeyStore(const std::string& directory, std::unique_ptr<IKeyStore>* out);
#endif

}  // namespace sg::client
