#pragma once
/**
 * @file
 * @brief Server-side license records and installation seats.
 *
 * License decisions are made exclusively on the server from these records;
 * a client's license id is only a claim used to look one up. A seat is an
 * activation: an installation keeps its seat until an administrator releases
 * it (or revokes the installation), not merely while it is connected.
 */

#include "sockgate_common/core/status.h"
#include "sockgate_common/protocol/constants.h"

#include <memory>
#include <string>

namespace sg::server {

/**
 * @brief Status of a license: kActive, or kRevoked (permanent: a revoked license cannot be updated, take new
 *        seats or authorize sessions).
 */
enum class LicenseStatus : uint8_t { kActive = 1, kRevoked = 2 };

/** @brief Maximum number of licenses in a store; enforced on every change (and on load). */
constexpr uint32_t kMaxLicenses = 1'000'000;
/** @brief Maximum number of seats of one license; enforced on every change (and on load). */
constexpr uint32_t kMaxSeatsPerLicense = 1'000'000;

/** @brief A license: its terms and (on output) its seat usage. */
struct LicenseRecord {
    std::string license_id;          ///< 1..128 bytes, protocol-safe string.
    std::string product_id;          ///< 1..64 bytes, protocol-safe string.
    uint64_t features = 0;           ///< Feature bits this license entitles.
    uint64_t expires_at_ms = 0;      ///< Unix ms, 0 = no expiry.
    uint32_t max_installations = 0;  ///< 0 = unlimited.
    LicenseStatus status = LicenseStatus::kActive;  ///< Reported by Find(); ignored by Upsert() (see Revoke()).
    uint32_t seats_used = 0;         ///< Output only.
};

/**
 * @brief License store interface: license terms and the seats (installations) bound to each license.
 *
 * @note The built-in implementations serialize every call with an internal mutex, so they may be used
 *       concurrently from any thread. The file store persists the whole state (atomic replace) on every
 *       change; a change whose write fails is rolled back, except a revocation.
 */
class ILicenseStore {
public:
    virtual ~ILicenseStore() = default;

    /**
     * @brief Looks up a license, with `seats_used` filled in.
     * @param[in]  license_id License id.
     * @param[out] out        Receives the record.
     * @retval SG_OK               Found.
     * @retval SG_NOT_FOUND        Unknown license.
     * @retval SG_INVALID_ARGUMENT @p out is null.
     */
    virtual Status Find(const std::string& license_id, LicenseRecord* out) = 0;
    /**
     * @brief Inserts a license or updates its terms (product, features, expiry, seat limit), keeping existing
     *        seats.
     *
     * Lowering the seat limit does not remove seats already bound.
     *
     * @param[in] record License terms (`status` and `seats_used` are ignored; the license is active).
     * @retval SG_OK               Stored (durable for a file store).
     * @retval SG_INVALID_ARGUMENT Invalid identifiers (see ValidateLicenseRecord()).
     * @retval SG_INVALID_STATE    Revocation is permanent: for a revoked license.
     * @retval SG_LIMIT_EXCEEDED   Beyond kMaxLicenses (or the file would exceed kMaxStorageFileSize).
     * @retval other               Persisting failed; nothing changed.
     */
    virtual Status Upsert(const LicenseRecord& record) = 0;
    /**
     * @brief Revokes a license (permanently); its seats are kept.
     *
     * Idempotent. If persisting fails the license stays revoked in memory and
     * SG_STORAGE_ERROR is returned: a revocation is never undone by I/O errors. A later successful write (any
     * change, or calling Revoke again) persists it.
     *
     * @param[in] license_id License id.
     * @retval SG_OK            Revoked (durable for a file store).
     * @retval SG_NOT_FOUND     Unknown license.
     * @retval SG_STORAGE_ERROR Revoked in memory only.
     */
    virtual Status Revoke(const std::string& license_id) = 0;
    /**
     * @brief Binds `installation` to the license (takes a seat).
     *
     * Idempotent; *newly_bound tells whether this call took the seat. Atomic and durable when it returns OK.
     * Checks only the license status and the seat limits: expiry and product are the caller's business.
     *
     * @param[in]  license_id   License id.
     * @param[in]  installation Installation taking the seat.
     * @param[out] newly_bound  Set to true if this call took the seat, false otherwise (also on errors).
     * @retval SG_OK               The installation holds a seat.
     * @retval SG_LIMIT_EXCEEDED   When all seats are taken (max_installations or kMaxSeatsPerLicense), or the
     *                             file would exceed kMaxStorageFileSize (nothing changed).
     * @retval SG_NOT_FOUND        Unknown license.
     * @retval SG_INVALID_STATE    Revoked license.
     * @retval SG_INVALID_ARGUMENT @p newly_bound is null.
     * @retval other               Persisting failed; nothing changed.
     */
    virtual Status BindSeat(const std::string& license_id, const proto::InstallationId& installation,
                            bool* newly_bound) = 0;
    /**
     * @brief Frees an installation's seat (also on a revoked license).
     * @param[in] license_id   License id.
     * @param[in] installation Installation holding the seat.
     * @retval SG_OK        Released (durable for a file store).
     * @retval SG_NOT_FOUND Unknown license, or the installation holds no seat on it.
     * @retval other        Persisting failed; the seat is kept.
     */
    virtual Status ReleaseSeat(const std::string& license_id, const proto::InstallationId& installation) = 0;
    /**
     * @brief Tells whether an installation holds a seat (regardless of the license status).
     * @param[in] license_id   License id.
     * @param[in] installation Installation.
     * @retval SG_OK        If `installation` holds a seat.
     * @retval SG_NOT_FOUND Otherwise (also for an unknown license).
     */
    virtual Status HasSeat(const std::string& license_id, const proto::InstallationId& installation) = 0;
    /**
     * @brief Number of licenses (active and revoked).
     * @return The count.
     */
    virtual size_t Count() = 0;
};

/**
 * @brief Creates a license store that lives only in memory (nothing is persisted).
 * @return The store.
 */
std::unique_ptr<ILicenseStore> CreateMemoryLicenseStore();
/**
 * @brief Opens (or creates) a license store persisted to a file.
 *
 * Loads the existing file, validating every record as untrusted input; a missing file is an empty store. Every
 * change atomically replaces the file (owner-only). Holds an exclusive lock on the store while open.
 *
 * @param[in]  path License file path.
 * @param[out] out  Receives the store.
 * @retval SG_OK               Opened.
 * @retval SG_INVALID_STATE    The store is locked by another holder (see LockStore()).
 * @retval SG_STORAGE_ERROR    The file or its lock cannot be accessed, or the file is malformed.
 * @retval SG_INVALID_ARGUMENT @p out is null or @p path is empty (or not valid UTF-8 on Windows).
 */
Status CreateFileLicenseStore(const std::string& path, std::unique_ptr<ILicenseStore>* out);

/**
 * @brief Validates a record's identifiers (lengths, protocol-safe strings).
 *
 * The license id must have 1..proto::kMaxLicenseIdLength bytes and the product id 1..proto::kMaxProductIdLength
 * bytes. The numeric terms (features, expiry, seat limit) are not checked.
 *
 * @param[in] record Record to check.
 * @retval SG_OK               Valid.
 * @retval SG_INVALID_ARGUMENT An identifier is empty, too long or not a protocol-safe string.
 */
Status ValidateLicenseRecord(const LicenseRecord& record);

/**
 * @brief Log-safe reference to a license id ("lic:" + 16 hex digits of its SHA-256).
 *
 * Ids may be bearer secrets when license activation is enabled.
 *
 * @param[in] license_id License id.
 * @return The reference, or "lic:?" if hashing fails.
 */
std::string LicenseLogRef(const std::string& license_id);

}  // namespace sg::server
