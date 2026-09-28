#include "storage/license_store.h"

#include "storage/atomic_file.h"

#include "sockgate_common/crypto/crypto.h"
#include "sockgate_common/serialization/reader.h"
#include "sockgate_common/serialization/writer.h"

#include <map>
#include <mutex>
#include <set>

namespace sg::server {
namespace {

constexpr uint32_t kLicenseMagic = 0x53474C43;  // "SGLC"
constexpr uint16_t kLicenseVersion = 1;

struct Entry {
    LicenseRecord terms;  // seats_used is derived from `seats`
    std::set<proto::InstallationId> seats;
};

class MemoryLicenseStore : public ILicenseStore {
public:
    Status Find(const std::string& license_id, LicenseRecord* out) override
    {
        if (out == nullptr) return SG_INVALID_ARGUMENT;
        std::lock_guard<std::mutex> lock(mutex_);
        auto it = licenses_.find(license_id);
        if (it == licenses_.end()) return SG_NOT_FOUND;
        *out = it->second.terms;
        out->seats_used = static_cast<uint32_t>(it->second.seats.size());
        return OkStatus();
    }

    Status Upsert(const LicenseRecord& record) override
    {
        SG_TRY(ValidateLicenseRecord(record));
        std::lock_guard<std::mutex> lock(mutex_);
        auto it = licenses_.find(record.license_id);
        const bool existed = it != licenses_.end();
        if (existed && it->second.terms.status != LicenseStatus::kActive) return SG_INVALID_STATE;
        if (!existed && licenses_.size() >= kMaxLicenses) return SG_LIMIT_EXCEEDED;
        const LicenseRecord previous = existed ? it->second.terms : LicenseRecord();
        LicenseRecord& target = licenses_[record.license_id].terms;
        target.license_id = record.license_id;
        target.product_id = record.product_id;
        target.features = record.features;
        target.expires_at_ms = record.expires_at_ms;
        target.max_installations = record.max_installations;
        target.status = LicenseStatus::kActive;
        target.seats_used = 0;
        const Status st = PersistLocked();
        if (!st.ok()) {
            if (existed) {
                licenses_[record.license_id].terms = previous;
            } else {
                licenses_.erase(record.license_id);
            }
        }
        return st;
    }

    Status Revoke(const std::string& license_id) override
    {
        std::lock_guard<std::mutex> lock(mutex_);
        auto it = licenses_.find(license_id);
        if (it == licenses_.end()) return SG_NOT_FOUND;
        if (it->second.terms.status == LicenseStatus::kRevoked) return OkStatus();
        it->second.terms.status = LicenseStatus::kRevoked;
        // Stays revoked in memory even if it cannot be persisted.
        return PersistLocked().ok() ? OkStatus() : Status(SG_STORAGE_ERROR);
    }

    Status BindSeat(const std::string& license_id, const proto::InstallationId& installation,
                    bool* newly_bound) override
    {
        if (newly_bound == nullptr) return SG_INVALID_ARGUMENT;
        *newly_bound = false;
        std::lock_guard<std::mutex> lock(mutex_);
        auto it = licenses_.find(license_id);
        if (it == licenses_.end()) return SG_NOT_FOUND;
        Entry& entry = it->second;
        if (entry.terms.status != LicenseStatus::kActive) return SG_INVALID_STATE;
        if (entry.seats.count(installation) != 0) return OkStatus();
        if (entry.terms.max_installations != 0 && entry.seats.size() >= entry.terms.max_installations) {
            return SG_LIMIT_EXCEEDED;
        }
        if (entry.seats.size() >= kMaxSeatsPerLicense) return SG_LIMIT_EXCEEDED;
        entry.seats.insert(installation);
        const Status st = PersistLocked();
        if (!st.ok()) {
            entry.seats.erase(installation);
            return st;
        }
        *newly_bound = true;
        return OkStatus();
    }

    Status ReleaseSeat(const std::string& license_id, const proto::InstallationId& installation) override
    {
        std::lock_guard<std::mutex> lock(mutex_);
        auto it = licenses_.find(license_id);
        if (it == licenses_.end()) return SG_NOT_FOUND;
        if (it->second.seats.erase(installation) == 0) return SG_NOT_FOUND;
        const Status st = PersistLocked();
        if (!st.ok()) it->second.seats.insert(installation);
        return st;
    }

    Status HasSeat(const std::string& license_id, const proto::InstallationId& installation) override
    {
        std::lock_guard<std::mutex> lock(mutex_);
        auto it = licenses_.find(license_id);
        if (it == licenses_.end() || it->second.seats.count(installation) == 0) return SG_NOT_FOUND;
        return OkStatus();
    }

    size_t Count() override
    {
        std::lock_guard<std::mutex> lock(mutex_);
        return licenses_.size();
    }

protected:
    virtual Status PersistLocked() { return OkStatus(); }

    std::mutex mutex_;
    std::map<std::string, Entry> licenses_;
};

// File format (big endian):
//   u32 magic "SGLC" | u16 version | u32 count | licenses
//   license: vec16 id | vec16 product | u64 features | u64 expires | u32 max_installations |
//            u8 status | u32 seat_count | seat_count * iid[16]
class FileLicenseStore final : public MemoryLicenseStore {
public:
    explicit FileLicenseStore(std::string path) : path_(std::move(path)) {}

    Status Load()
    {
        Bytes data;
        const Status st = ReadWholeFile(path_, &data);
        if (st == SG_NOT_FOUND) return OkStatus();
        SG_TRY(st);
        return Parse(data);
    }

private:
    Status Parse(const Bytes& data)
    {
        ser::Reader r(data);
        uint32_t magic = 0;
        uint16_t version = 0;
        uint32_t count = 0;
        if (!r.U32(&magic).ok() || magic != kLicenseMagic || !r.U16(&version).ok() || version != kLicenseVersion ||
            !r.U32(&count).ok() || count > kMaxLicenses) {
            return SG_STORAGE_ERROR;
        }
        for (uint32_t i = 0; i < count; ++i) {
            Entry entry;
            LicenseRecord& rec = entry.terms;
            ByteView id;
            ByteView product;
            uint8_t status = 0;
            uint32_t seats = 0;
            if (!r.Vec16(1, proto::kMaxLicenseIdLength, &id).ok() ||
                !r.Vec16(1, proto::kMaxProductIdLength, &product).ok() || !r.U64(&rec.features).ok() ||
                !r.U64(&rec.expires_at_ms).ok() || !r.U32(&rec.max_installations).ok() || !r.U8(&status).ok() ||
                !r.U32(&seats).ok() || seats > kMaxSeatsPerLicense) {
                return SG_STORAGE_ERROR;
            }
            rec.license_id.assign(reinterpret_cast<const char*>(id.data()), id.size());
            rec.product_id.assign(reinterpret_cast<const char*>(product.data()), product.size());
            if (status != static_cast<uint8_t>(LicenseStatus::kActive) &&
                status != static_cast<uint8_t>(LicenseStatus::kRevoked)) {
                return SG_STORAGE_ERROR;
            }
            rec.status = static_cast<LicenseStatus>(status);
            for (uint32_t k = 0; k < seats; ++k) {
                proto::InstallationId iid;
                if (!r.Fixed(&iid).ok() || !entry.seats.insert(iid).second) return SG_STORAGE_ERROR;
            }
            if (!ValidateLicenseRecord(rec).ok() || licenses_.count(rec.license_id) != 0) return SG_STORAGE_ERROR;
            const std::string key = rec.license_id;
            licenses_[key] = std::move(entry);
        }
        return r.ExpectEnd().ok() ? OkStatus() : Status(SG_STORAGE_ERROR);
    }

    Status PersistLocked() override
    {
        Bytes out;
        ser::Writer w(&out);
        w.U32(kLicenseMagic);
        w.U16(kLicenseVersion);
        w.U32(static_cast<uint32_t>(licenses_.size()));
        for (const auto& item : licenses_) {
            const LicenseRecord& rec = item.second.terms;
            SG_TRY(w.Vec16(ser::AsBytes(rec.license_id)));
            SG_TRY(w.Vec16(ser::AsBytes(rec.product_id)));
            w.U64(rec.features);
            w.U64(rec.expires_at_ms);
            w.U32(rec.max_installations);
            w.U8(static_cast<uint8_t>(rec.status));
            w.U32(static_cast<uint32_t>(item.second.seats.size()));
            for (const auto& iid : item.second.seats) w.Raw(iid);
        }
        // Never write a file that Load() would refuse.
        if (out.size() > kMaxStorageFileSize) return SG_LIMIT_EXCEEDED;
        return WriteFileAtomically(path_, out);
    }

    const std::string path_;
};

}  // namespace

Status ValidateLicenseRecord(const LicenseRecord& record)
{
    if (record.license_id.empty() || record.license_id.size() > proto::kMaxLicenseIdLength ||
        !ser::IsValidProtocolString(ser::AsBytes(record.license_id))) {
        return SG_INVALID_ARGUMENT;
    }
    if (record.product_id.empty() || record.product_id.size() > proto::kMaxProductIdLength ||
        !ser::IsValidProtocolString(ser::AsBytes(record.product_id))) {
        return SG_INVALID_ARGUMENT;
    }
    return OkStatus();
}

std::string LicenseLogRef(const std::string& license_id)
{
    crypto::Sha256Digest digest{};
    if (!crypto::Sha256(ser::AsBytes(license_id), &digest).ok()) return "lic:?";
    return "lic:" + ToHex(ByteView(digest.data(), 8));
}

std::unique_ptr<ILicenseStore> CreateMemoryLicenseStore() { return std::make_unique<MemoryLicenseStore>(); }

Status CreateFileLicenseStore(const std::string& path, std::unique_ptr<ILicenseStore>* out)
{
    if (out == nullptr || path.empty()) return SG_INVALID_ARGUMENT;
    auto store = std::make_unique<FileLicenseStore>(path);
    SG_TRY(store->Load());
    *out = std::move(store);
    return OkStatus();
}

}  // namespace sg::server
