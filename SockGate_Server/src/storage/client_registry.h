#pragma once
/**
 * @file
 * @brief Server-side registry of client installations (public keys + status) and of consumed enrollment
 *        tokens.
 */

#include "sockgate_common/core/status.h"
#include "sockgate_common/crypto/crypto.h"
#include "sockgate_common/protocol/constants.h"
#include "sockgate_common/protocol/enrollment_token.h"

#include <functional>
#include <memory>
#include <string>
#include <vector>

namespace sg::server {

/**
 * @brief Status of a registered installation: kActive (may authenticate) or kRevoked (permanently refused; the
 *        installation id cannot be registered again).
 */
enum class ClientStatus : uint8_t { kActive = 1, kRevoked = 2 };

/**
 * @brief A registered installation. The registry's bindings are server-trusted and override client claims.
 *
 * Registration and enrollment validate the record: key algorithm ECDSA P-256, a valid public key, an
 * installation id derived from that key, a known status and bounded binding lengths.
 */
struct ClientRecord {
    proto::InstallationId installation_id{};  ///< Installation id; must be derived from #public_key.
    crypto::P256PublicKey public_key{};       ///< The installation's P-256 public key.
    uint8_t key_algorithm = proto::kKeyAlgorithmEcdsaP256Sha256;  ///< Key algorithm (only ECDSA P-256/SHA-256).
    ClientStatus status = ClientStatus::kActive;  ///< Active or revoked.
    std::string product_id;   ///< Optional binding (at most proto::kMaxProductIdLength bytes).
    std::string license_id;   ///< Optional binding (at most proto::kMaxLicenseIdLength bytes).
    uint64_t created_at_ms = 0;  ///< Registration time, Unix ms.
};

/**
 * @brief Installation registry interface.
 *
 * @note The built-in implementations serialize every call with an internal mutex and never run caller code
 *       while holding it, so they may be used concurrently from any thread. The file registry persists the whole
 *       state (atomic replace) on every change; a change whose write fails is rolled back, except a revocation.
 */
class IClientRegistry {
public:
    virtual ~IClientRegistry() = default;

    /**
     * @brief Looks up an installation.
     * @param[in]  id  Installation id.
     * @param[out] out Receives a copy of the record.
     * @retval SG_OK               Found.
     * @retval SG_NOT_FOUND        When unknown.
     * @retval SG_INVALID_ARGUMENT @p out is null.
     */
    virtual Status Find(const proto::InstallationId& id, ClientRecord* out) = 0;

    /**
     * @brief Registers an installation.
     * @param[in] record Record to insert (validated).
     * @retval SG_OK               Registered (durable for a file registry).
     * @retval SG_ALREADY_EXISTS   If the installation id is known (active or revoked).
     * @retval SG_INVALID_ARGUMENT Invalid record.
     * @retval other               Persisting failed; nothing changed.
     */
    virtual Status Register(const ClientRecord& record) = 0;

    /**
     * @brief Revokes an installation.
     *
     * Idempotent for already revoked records. If
     * persisting fails the record stays revoked in memory and
     * SG_STORAGE_ERROR is returned: I/O errors never undo a revocation. A later successful write (any change,
     * or calling Revoke again) persists it.
     *
     * @param[in] id Installation id.
     * @retval SG_OK            Revoked (durable for a file registry).
     * @retval SG_NOT_FOUND     When unknown.
     * @retval SG_STORAGE_ERROR Revoked in memory only.
     */
    virtual Status Revoke(const proto::InstallationId& id) = 0;

    /**
     * @brief Atomically consumes `token_id` and inserts `record`.
     *
     * Fails without any
     * change with SG_ALREADY_EXISTS if either the token was already used or
     * the installation id is known. The change is durable when this returns OK.
     *
     * @param[in] record              Record to insert (validated).
     * @param[in] token_id            Enrollment token id to consume.
     * @param[in] token_expires_at_ms Token expiry (Unix ms) stored with the consumed id; 0 if unknown.
     * @retval SG_OK               Consumed and inserted.
     * @retval SG_ALREADY_EXISTS   Token already used, or installation id known.
     * @retval SG_INVALID_ARGUMENT Invalid record.
     * @retval other               Persisting failed; nothing changed.
     */
    virtual Status EnrollAtomically(const ClientRecord& record, const proto::TokenId& token_id,
                                    uint64_t token_expires_at_ms) = 0;

    /**
     * @brief Tells whether an enrollment token id was consumed.
     * @param[in] token_id Token id.
     * @return True if consumed.
     */
    virtual bool IsTokenUsed(const proto::TokenId& token_id) = 0;

    /**
     * @brief Pins a license (and the product, if still unbound) to an installation.
     *
     * Only an installation that has no license binding yet is bound: first binding wins.
     *
     * @param[in] id         Installation id.
     * @param[in] product_id Product of the license; required.
     * @param[in] license_id License to pin; required.
     * @retval SG_OK               Bound (durable for a file registry), or already bound to exactly this license.
     * @retval SG_ALREADY_EXISTS   Bound to another license.
     * @retval SG_INVALID_ARGUMENT On a product conflict, or an empty or overlong product or license id.
     * @retval SG_INVALID_STATE    If revoked.
     * @retval SG_NOT_FOUND        Unknown installation.
     * @retval other               Persisting failed; nothing changed.
     */
    virtual Status BindLicense(const proto::InstallationId& id, const std::string& product_id,
                               const std::string& license_id) = 0;

    /**
     * @brief Number of registered installations (active and revoked).
     * @return The count.
     */
    virtual size_t Count() = 0;
    /**
     * @brief Calls @p fn for every record.
     *
     * The built-in implementations iterate over a copy taken under the lock, so @p fn may call back into the
     * registry.
     *
     * @param[in] fn Visitor.
     */
    virtual void ForEach(const std::function<void(const ClientRecord&)>& fn) = 0;
};

/**
 * @brief Creates a registry that lives only in memory (nothing is persisted).
 * @return The registry.
 */
std::unique_ptr<IClientRegistry> CreateMemoryClientRegistry();

/**
 * @brief Opens (or creates) a registry persisted to a file.
 *
 * Registry persisted to `path` (atomic replace on every change, owner-only file). Loads the
 * existing file, validating every record as untrusted input; a missing file is an empty registry. Holds an
 * exclusive lock on the store while open: SG_INVALID_STATE if it is in use.
 *
 * @param[in]  path Registry file path.
 * @param[out] out  Receives the registry.
 * @retval SG_OK               Opened.
 * @retval SG_INVALID_STATE    The store is locked by another holder (see LockStore()).
 * @retval SG_STORAGE_ERROR    The file or its lock cannot be accessed, or the file is malformed.
 * @retval SG_INVALID_ARGUMENT @p out is null or @p path is empty (or not valid UTF-8 on Windows).
 */
Status CreateFileClientRegistry(const std::string& path, std::unique_ptr<IClientRegistry>* out);

}  // namespace sg::server
