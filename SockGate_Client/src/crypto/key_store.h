#pragma once
/**
 * @file
 * @brief Installation key storage abstraction (IKeyStore).
 *
 * Core code refers to keys only by name and asks the store to sign; it never sees private key bytes.
 * Implementations:
 * @verbatim
   MemoryKeyStore   process memory (tests, ephemeral identities)
   FileKeyStore     PKCS#8 file (0600 on Linux, DPAPI-wrapped on Windows)
   CngKeyStore      Windows CNG, TPM (Platform Crypto Provider) or software KSP
   Tpm2KeyStore     Linux TPM2 via tpm2-tss (optional build)
   @endverbatim
 * AUTO (CreateAutoKeyStore()) combines several of them.
 */

#include "sockgate_common/core/bytes.h"
#include "sockgate_common/core/status.h"
#include "sockgate_common/crypto/crypto.h"
#include "sockgate_common/protocol/constants.h"

#include <memory>
#include <string>
#include <vector>

namespace sg::client {

/**
 * @brief Type of a key store; reported to the application as the matching SG_KEYSTORE_* value.
 *
 * The numeric values are persisted in AUTO locator files (see CreateAutoKeyStore()).
 */
enum class KeyStoreKind : uint32_t {
    kMemory = 1,       ///< Process memory, no persistence.
    kFile = 2,         ///< Protected PKCS#8 file per key.
    kCngSoftware = 3,  ///< Windows CNG, Microsoft Software KSP.
    kCngTpm = 4,       ///< Windows CNG, Microsoft Platform Crypto Provider (TPM).
    kTpm2 = 5,         ///< Linux TPM 2.0 through tpm2-tss.
};

/**
 * @brief Short name of @p kind for logs.
 * @param[in] kind Store type.
 * @return "memory", "file", "cng-software", "cng-tpm" or "tpm2"; "unknown" for any other value. Static storage.
 */
const char* KeyStoreKindName(KeyStoreKind kind) noexcept;

/**
 * @brief Named ECDSA P-256 installation keys held by one storage backend.
 *
 * Keys are referred to by name (see ValidateKeyName()); the store signs on request and private key bytes never
 * leave it. Only SG_NOT_FOUND means "no such key": any other failure means the store could not answer, which AUTO
 * relies on to never replace an identity that is merely unreachable.
 *
 * @note A ClientSession calls its store without a session lock from EnsureIdentity() / GetIdentity() and under its
 *       control lock from Authenticate(), Refresh() and DeleteIdentity(), so calls may overlap. The implementations
 *       in this library guard their mutable state (a mutex in the memory and TPM2 stores, an atomic in the CNG
 *       store) or keep none.
 */
class IKeyStore {
public:
    virtual ~IKeyStore() = default;

    /**
     * @brief Type of this store.
     * @return The store type; for AUTO, the type of its first (strongest) store.
     */
    virtual KeyStoreKind Kind() const noexcept = 0;
    /**
     * @brief True when the private key cannot leave a hardware boundary (TPM).
     *
     * For AUTO this describes the first store; Describe() reports the store that holds a given key.
     *
     * @note A local fact, not attestation: nothing proves it to the server.
     *
     * @return True for TPM-backed stores.
     */
    virtual bool HardwareBacked() const noexcept = 0;

    /**
     * @brief Creates a new ECDSA P-256 key.
     *
     * SG_ALREADY_EXISTS if the name is taken (creation is exclusive, so concurrent creators cannot both succeed).
     *
     * @param[in] name Key name (ValidateKeyName()).
     * @retval SG_OK               Key created.
     * @retval SG_ALREADY_EXISTS   A key with this name exists.
     * @retval SG_INVALID_ARGUMENT @p name is not a valid key name.
     * @retval SG_NOT_SUPPORTED    This store definitely cannot create the key here (AUTO then tries the next store).
     * @retval SG_IDENTITY_LOST    (AUTO) A locator records this name but its store no longer has the key.
     * @retval SG_KEYSTORE_ERROR   Storage failure, including transient TPM trouble.
     */
    virtual Status GenerateKeyPair(const std::string& name) = 0;

    /**
     * @brief Reads the public key of @p name.
     *
     * SG_NOT_FOUND if the key does not exist.
     *
     * @param[in]  name Key name.
     * @param[out] out  Receives the public key (SEC1 uncompressed).
     * @retval SG_OK               Public key returned.
     * @retval SG_NOT_FOUND        No such key.
     * @retval SG_INVALID_ARGUMENT @p out is nullptr, or @p name is not a valid key name.
     * @retval SG_IDENTITY_LOST    (AUTO) The recorded store works but no longer has the key.
     * @retval SG_KEYSTORE_ERROR   The store could not answer, or the stored key is invalid.
     */
    virtual Status GetPublicKey(const std::string& name, crypto::P256PublicKey* out) = 0;

    /**
     * @brief Signs @p message with the key @p name.
     *
     * ECDSA-P256-SHA256 over `message` (the store hashes), P1363 output.
     *
     * @param[in]  name    Key name.
     * @param[in]  message Bytes to sign (not a digest).
     * @param[out] out     Receives r || s (64 bytes).
     * @retval SG_OK               Signature produced.
     * @retval SG_NOT_FOUND        No such key.
     * @retval SG_INVALID_ARGUMENT @p out is nullptr, or @p name is not a valid key name.
     * @retval SG_IDENTITY_LOST    (AUTO) The recorded store works but no longer has the key.
     * @retval SG_KEYSTORE_ERROR   The store failed, e.g. the TPM is unreachable or cannot load the key.
     */
    virtual Status Sign(const std::string& name, ByteView message, crypto::P256Signature* out) = 0;

    /**
     * @brief Deletes the key @p name.
     *
     * File-based keys are overwritten with zeros before removal (best effort: the medium may keep old blocks).
     *
     * @param[in] name Key name.
     * @retval SG_OK             Deleted.
     * @retval SG_NOT_FOUND      No such key.
     * @retval SG_KEYSTORE_ERROR Deletion failed; for AUTO also while the recorded store is unavailable (see
     *                           ForceDeleteKey()).
     */
    virtual Status DeleteKey(const std::string& name) = 0;
    /**
     * @brief Like DeleteKey, but also forgets an identity whose store is currently unavailable (AUTO); a key in that
     *        store may survive. Explicit reset only.
     *
     * The default implementation calls DeleteKey().
     *
     * @param[in] name Key name.
     * @return As DeleteKey(). AUTO deletes the key from every store, ignoring store errors, and removes the locator:
     *         SG_OK once the locator is removed, even if keys in failing stores remain; without a locator, SG_OK if
     *         some store deleted the key and SG_NOT_FOUND otherwise, even when stores failed. An error removing the
     *         locator is returned.
     */
    virtual Status ForceDeleteKey(const std::string& name) { return DeleteKey(name); }

    /**
     * @brief Public key and the store actually holding it, from one lookup (differs from Kind() only for AUTO).
     *
     * @param[in]  name            Key name.
     * @param[out] public_key      Receives the public key (SEC1 uncompressed).
     * @param[out] kind            Receives the type of the store holding the key.
     * @param[out] hardware_backed Receives whether that store is hardware backed.
     * @retval SG_OK               All outputs set.
     * @retval SG_INVALID_ARGUMENT An output pointer is nullptr.
     * @return Otherwise the GetPublicKey() error.
     */
    virtual Status Describe(const std::string& name, crypto::P256PublicKey* public_key, KeyStoreKind* kind,
                            bool* hardware_backed);
};

/**
 * @brief Checks a key name.
 *
 * Key names are restricted to [A-Za-z0-9._-], 1..128 characters, so they can be used safely as file names and CNG
 * key names; a leading '.' is refused, and Windows device names (CON, NUL, COM1, ...) are refused on every
 * platform. Names are shared by all applications of a user: use a reverse-DNS style name ("com.example.app").
 *
 * @param[in] name Candidate key name.
 * @retval SG_OK               Valid.
 * @retval SG_INVALID_ARGUMENT Not a valid key name.
 */
Status ValidateKeyName(const std::string& name);

/** @brief Installation identity as seen through a key store (EnsureIdentity(), GetIdentity()). */
struct IdentityInfo {
    crypto::P256PublicKey public_key{};        ///< Public key (SEC1 uncompressed), validated as a P-256 point.
    proto::InstallationId installation_id{};   ///< Derived from public_key (proto::DeriveInstallationId()).
    KeyStoreKind kind = KeyStoreKind::kMemory;  ///< Store actually holding the key.
    bool hardware_backed = false;              ///< That store is TPM-backed (a local fact, not attestation).
    bool created = false;  ///< True if EnsureIdentity generated a new key.
};

/**
 * @brief Loads the named identity, creating it when absent (tolerates a concurrent creator winning the race).
 *
 * The installation id is derived from the key. Only SG_NOT_FOUND from the lookup leads to creation; any other
 * lookup error is returned and no key is created.
 *
 * @param[in]  store Key store to use.
 * @param[in]  name  Key name.
 * @param[out] out   Receives the identity; created is true only if this call generated the key.
 * @retval SG_OK               Identity loaded or created.
 * @retval SG_INVALID_ARGUMENT @p out is nullptr, or @p name is not a valid key name.
 * @retval SG_NOT_SUPPORTED    No store can create the key.
 * @retval SG_IDENTITY_LOST    (AUTO) The recorded store no longer has the key.
 * @retval SG_KEYSTORE_ERROR   The store failed or is unavailable.
 */
Status EnsureIdentity(IKeyStore& store, const std::string& name, IdentityInfo* out);
/**
 * @brief Loads the named identity without creating it.
 *
 * Validates the public key as a P-256 point and derives the installation id; created is false.
 *
 * @param[in]  store Key store to use.
 * @param[in]  name  Key name.
 * @param[out] out   Receives the identity.
 * @retval SG_OK               Identity loaded.
 * @retval SG_NOT_FOUND        No such key.
 * @retval SG_INVALID_ARGUMENT @p out is nullptr, or @p name is not a valid key name.
 * @retval SG_IDENTITY_LOST    (AUTO) The recorded store no longer has the key.
 * @retval SG_KEYSTORE_ERROR   The store failed or is unavailable.
 */
Status GetIdentity(IKeyStore& store, const std::string& name, IdentityInfo* out);

/**
 * @brief In-memory key store (no persistence).
 * @return A new store (kMemory, not hardware backed); its keys are lost with the object.
 */
std::unique_ptr<IKeyStore> CreateMemoryKeyStore();

/**
 * @brief FILE key store in `directory` ("" = per-user default, see platform/key_file.h).
 *
 * One file per key; DPAPI-protected on Windows, owner-only (0600) on Linux. Each key lives in "<name>.sgkey"
 * together with its public key; on every use the private key is unwrapped, checked against the stored public key
 * (pairwise signing check) and held in memory only for that call. The directory is created and verified here.
 *
 * @warning Not equivalent to a TPM. On Linux the PKCS#8 key is stored unencrypted and protected only by file
 *          permissions.
 *
 * @param[in]  directory Key directory; "" selects os::DefaultKeyDirectory().
 * @param[out] out       Receives the store.
 * @retval SG_OK               Store created.
 * @retval SG_INVALID_ARGUMENT @p out is nullptr or @p directory is unusable as a path.
 * @retval SG_NOT_FOUND        (Windows) The directory cannot be created (os::PrepareKeyDirectory()).
 * @retval SG_KEYSTORE_ERROR   No default directory, or the directory fails the ownership and permission checks or
 *                             (Linux) cannot be created (os::PrepareKeyDirectory()).
 */
Status CreateFileKeyStore(const std::string& directory, std::unique_ptr<IKeyStore>* out);

/**
 * @brief AUTO key store over @p stores, strongest first.
 *
 * AUTO: keys are looked up in every store; new keys are created in the first (strongest) store that supports key
 * creation (only SG_NOT_SUPPORTED moves on to the next store). A locator file per identity ("<name>.sgref") in
 * `locator_directory` ("" = per-user default) records the store that created it, and only that store is asked
 * afterwards:
 * @verbatim
   store not available (TPM provider cannot be opened) -> SG_KEYSTORE_ERROR
   store available but the key is gone                 -> SG_IDENTITY_LOST
   @endverbatim
 * Neither case creates a replacement identity. "Gone" means the store reports SG_NOT_FOUND. A TPM clear shows up
 * there only if the store then reports the key absent; a Linux TPM2 key file survives a clear, so the lookup
 * succeeds and Sign() fails with SG_KEYSTORE_ERROR. A key found without a locator (created before locators existed)
 * gets one on its first lookup.
 *
 * DeleteKey refuses while the recorded store is unavailable; ForceDeleteKey forgets the identity anyway. Stores
 * never degrade to process memory. Kind() and HardwareBacked() describe the first store.
 *
 * @param[in]  stores            Stores, strongest first (taken over); none may be nullptr or kMemory.
 * @param[in]  locator_directory Locator directory; "" selects os::DefaultKeyDirectory().
 * @param[out] out               Receives the store.
 * @retval SG_OK               Store created.
 * @retval SG_INVALID_ARGUMENT @p out is nullptr, @p stores is empty or contains nullptr or a memory store.
 * @retval SG_NOT_FOUND        (Windows) The locator directory cannot be created.
 * @retval SG_KEYSTORE_ERROR   The locator directory cannot be determined or verified, or (Linux) created.
 */
Status CreateAutoKeyStore(std::vector<std::unique_ptr<IKeyStore>> stores, const std::string& locator_directory,
                          std::unique_ptr<IKeyStore>* out);

#ifdef _WIN32
/**
 * @brief Windows CNG key store.
 *
 * Windows CNG: Microsoft Platform Crypto Provider (TPM) when `tpm`, else the Microsoft Software KSP (non-exportable
 * per-user keys). SG_NOT_SUPPORTED if the provider is unavailable. GenerateKeyPair returns SG_NOT_SUPPORTED only
 * for definite answers (no TPM 2.0, algorithm unsupported, owner hierarchy disabled; TPM provider only); transient
 * failures are SG_KEYSTORE_ERROR. Existing keys are always looked up, and lookup failures are errors, never "key
 * absent".
 *
 * Keys are persisted per user as "SockGate-<name>", usable for signing only; private keys are never exported (the
 * TPM keeps them inside the chip). Whether the TPM is a TPM 2.0 is asked when the store is created; if that answer
 * is not known yet, the next GenerateKeyPair() asks again. No UI is shown.
 *
 * @param[in]  tpm True for the Platform Crypto Provider (TPM), false for the Software KSP.
 * @param[out] out Receives the store.
 * @retval SG_OK               Store created.
 * @retval SG_INVALID_ARGUMENT @p out is nullptr.
 * @retval SG_NOT_SUPPORTED    The provider cannot be opened.
 */
Status CreateCngKeyStore(bool tpm, std::unique_ptr<IKeyStore>* out);
#endif

#ifdef SOCKGATE_WITH_TPM2
/**
 * @brief Linux TPM 2.0 key store.
 *
 * Linux TPM2 (tpm2-tss ESAPI): keys never leave the TPM; TPM-wrapped key blobs are kept in `directory`
 * (owner-only, like FILE keys). The TPM is reached through /dev/tpmrm0 or SOCKGATE_TPM2_TCTI (device/tabrmd/swtpm/
 * mssim only; simulators are for testing). GenerateKeyPair returns SG_NOT_SUPPORTED only for definite answers (no
 * TPM access, owner auth set, owner hierarchy disabled, algorithm unsupported); existing keys are always found.
 *
 * Each key is created under a primary storage key re-derived on demand from a fixed template in the owner
 * hierarchy (nothing is persisted in the TPM) and stored as "<name>.tpm2key". The TCTI is chosen once, here
 * (SOCKGATE_TPM2_TCTI is read with secure_getenv()): without one, GenerateKeyPair() returns SG_NOT_SUPPORTED and
 * Sign() SG_KEYSTORE_ERROR for the life of the store. Lookups read only the blob file, so they still succeed after
 * a TPM clear while Sign() fails with SG_KEYSTORE_ERROR. Every signature is verified with the public key before it
 * is returned. ESAPI access is serialised by a mutex.
 *
 * @param[in]  directory Blob directory; "" selects os::DefaultKeyDirectory().
 * @param[out] out       Receives the store.
 * @retval SG_OK               Store created (also when no TPM is reachable).
 * @retval SG_INVALID_ARGUMENT @p out is nullptr, or SOCKGATE_TPM2_TCTI names a TCTI other than those listed.
 * @retval SG_KEYSTORE_ERROR   The directory cannot be determined, created or verified.
 */
Status CreateTpm2KeyStore(const std::string& directory, std::unique_ptr<IKeyStore>* out);
#endif

}  // namespace sg::client
