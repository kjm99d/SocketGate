// Server-side license records and installation seats.
//
// License decisions are made exclusively on the server from these records;
// a client's license id is only a claim used to look one up. A seat is an
// activation: an installation keeps its seat until an administrator releases
// it (or revokes the installation), not merely while it is connected.
#pragma once

#include "sockgate_common/core/status.h"
#include "sockgate_common/protocol/constants.h"

#include <memory>
#include <string>

namespace sg::server {

enum class LicenseStatus : uint8_t { kActive = 1, kRevoked = 2 };

// Limits enforced on every change (and on load).
constexpr uint32_t kMaxLicenses = 1'000'000;
constexpr uint32_t kMaxSeatsPerLicense = 1'000'000;

struct LicenseRecord {
    std::string license_id;          // 1..128
    std::string product_id;          // 1..64
    uint64_t features = 0;           // feature bits this license entitles
    uint64_t expires_at_ms = 0;      // Unix ms, 0 = no expiry
    uint32_t max_installations = 0;  // 0 = unlimited
    LicenseStatus status = LicenseStatus::kActive;
    uint32_t seats_used = 0;         // output only
};

class ILicenseStore {
public:
    virtual ~ILicenseStore() = default;

    virtual Status Find(const std::string& license_id, LicenseRecord* out) = 0;  // SG_NOT_FOUND
    // Inserts a license or updates its terms (product, features, expiry, seat
    // limit), keeping existing seats. Revocation is permanent: SG_INVALID_STATE
    // for a revoked license. SG_LIMIT_EXCEEDED beyond kMaxLicenses.
    virtual Status Upsert(const LicenseRecord& record) = 0;
    // Idempotent. If persisting fails the license stays revoked in memory and
    // SG_STORAGE_ERROR is returned: a revocation is never undone by I/O errors.
    virtual Status Revoke(const std::string& license_id) = 0;
    // Binds `installation` to the license (idempotent; *newly_bound tells
    // whether this call took the seat). SG_LIMIT_EXCEEDED when all seats are
    // taken, SG_NOT_FOUND / SG_INVALID_STATE for unknown or revoked licenses.
    // Atomic and durable when it returns OK.
    virtual Status BindSeat(const std::string& license_id, const proto::InstallationId& installation,
                            bool* newly_bound) = 0;
    virtual Status ReleaseSeat(const std::string& license_id, const proto::InstallationId& installation) = 0;
    // OK if `installation` holds a seat, SG_NOT_FOUND otherwise.
    virtual Status HasSeat(const std::string& license_id, const proto::InstallationId& installation) = 0;
    virtual size_t Count() = 0;
};

std::unique_ptr<ILicenseStore> CreateMemoryLicenseStore();
Status CreateFileLicenseStore(const std::string& path, std::unique_ptr<ILicenseStore>* out);

// Validates identifiers and terms (lengths, protocol-safe strings).
Status ValidateLicenseRecord(const LicenseRecord& record);

// Log-safe reference to a license id ("lic:" + 16 hex digits of its SHA-256):
// ids may be bearer secrets when license activation is enabled.
std::string LicenseLogRef(const std::string& license_id);

}  // namespace sg::server
