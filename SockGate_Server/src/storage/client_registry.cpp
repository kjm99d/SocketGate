#include "storage/client_registry.h"

#include "storage/atomic_file.h"

#include "sockgate_common/protocol/transcript.h"
#include "sockgate_common/serialization/reader.h"
#include "sockgate_common/serialization/writer.h"

#include <map>
#include <mutex>

namespace sg::server {
namespace {

constexpr uint32_t kRegistryMagic = 0x53475247;  // "SGRG"
constexpr uint16_t kRegistryVersion = 1;
constexpr uint32_t kMaxRecords = 10'000'000;

struct TokenEntry {
    uint64_t expires_at_ms = 0;
};

class MemoryRegistry : public IClientRegistry {
public:
    Status Find(const proto::InstallationId& id, ClientRecord* out) override
    {
        if (out == nullptr) return SG_INVALID_ARGUMENT;
        std::lock_guard<std::mutex> lock(mutex_);
        auto it = records_.find(id);
        if (it == records_.end()) return SG_NOT_FOUND;
        *out = it->second;
        return OkStatus();
    }

    Status Register(const ClientRecord& record) override
    {
        SG_TRY(Validate(record));
        std::lock_guard<std::mutex> lock(mutex_);
        if (records_.count(record.installation_id) != 0) return SG_ALREADY_EXISTS;
        records_[record.installation_id] = record;
        const Status st = PersistLocked();
        if (!st.ok()) records_.erase(record.installation_id);
        return st;
    }

    Status Revoke(const proto::InstallationId& id) override
    {
        std::lock_guard<std::mutex> lock(mutex_);
        auto it = records_.find(id);
        if (it == records_.end()) return SG_NOT_FOUND;
        if (it->second.status == ClientStatus::kRevoked) return OkStatus();
        it->second.status = ClientStatus::kRevoked;
        return PersistLocked().ok() ? OkStatus() : Status(SG_STORAGE_ERROR);
    }

    Status EnrollAtomically(const ClientRecord& record, const proto::TokenId& token_id,
                            uint64_t token_expires_at_ms) override
    {
        SG_TRY(Validate(record));
        std::lock_guard<std::mutex> lock(mutex_);
        if (tokens_.count(token_id) != 0 || records_.count(record.installation_id) != 0) return SG_ALREADY_EXISTS;
        records_[record.installation_id] = record;
        tokens_[token_id] = TokenEntry{token_expires_at_ms};
        const Status st = PersistLocked();
        if (!st.ok()) {
            records_.erase(record.installation_id);
            tokens_.erase(token_id);
        }
        return st;
    }

    bool IsTokenUsed(const proto::TokenId& token_id) override
    {
        std::lock_guard<std::mutex> lock(mutex_);
        return tokens_.count(token_id) != 0;
    }

    Status BindLicense(const proto::InstallationId& id, const std::string& product_id,
                       const std::string& license_id) override
    {
        if (product_id.empty() || product_id.size() > proto::kMaxProductIdLength || license_id.empty() ||
            license_id.size() > proto::kMaxLicenseIdLength) {
            return SG_INVALID_ARGUMENT;
        }
        std::lock_guard<std::mutex> lock(mutex_);
        auto it = records_.find(id);
        if (it == records_.end()) return SG_NOT_FOUND;
        ClientRecord& rec = it->second;
        if (rec.status != ClientStatus::kActive) return SG_INVALID_STATE;
        if (!rec.license_id.empty()) return rec.license_id == license_id ? OkStatus() : Status(SG_ALREADY_EXISTS);
        if (!rec.product_id.empty() && rec.product_id != product_id) return SG_INVALID_ARGUMENT;
        const ClientRecord previous = rec;
        rec.product_id = product_id;
        rec.license_id = license_id;
        const Status st = PersistLocked();
        if (!st.ok()) rec = previous;
        return st;
    }

    size_t Count() override
    {
        std::lock_guard<std::mutex> lock(mutex_);
        return records_.size();
    }

    void ForEach(const std::function<void(const ClientRecord&)>& fn) override
    {
        std::vector<ClientRecord> copy;
        {
            std::lock_guard<std::mutex> lock(mutex_);
            for (const auto& entry : records_) copy.push_back(entry.second);
        }
        for (const auto& r : copy) fn(r);
    }

protected:
    static Status Validate(const ClientRecord& r)
    {
        if (r.key_algorithm != proto::kKeyAlgorithmEcdsaP256Sha256) return SG_INVALID_ARGUMENT;
        if (r.status != ClientStatus::kActive && r.status != ClientStatus::kRevoked) return SG_INVALID_ARGUMENT;
        if (r.product_id.size() > proto::kMaxProductIdLength || r.license_id.size() > proto::kMaxLicenseIdLength) {
            return SG_INVALID_ARGUMENT;
        }
        SG_TRY(crypto::ValidateP256PublicKey(r.public_key));
        // The installation id is bound to the key; a mismatching record is refused.
        proto::InstallationId derived;
        SG_TRY(proto::DeriveInstallationId(r.public_key, &derived));
        if (derived != r.installation_id) return SG_INVALID_ARGUMENT;
        return OkStatus();
    }

    virtual Status PersistLocked() { return OkStatus(); }

    std::mutex mutex_;
    std::map<proto::InstallationId, ClientRecord> records_;
    std::map<proto::TokenId, TokenEntry> tokens_;
};

// ---- file-backed registry ------------------------------------------------------
//
// File format (big endian):
//   u32 magic "SGRG" | u16 version | u32 record_count | records | u32 token_count | tokens
//   record: iid[16] | pubkey[65] | u8 alg | u8 status | vec16 product | vec16 license | u64 created_at
//   token:  token_id[16] | u64 expires_at

class FileRegistry final : public MemoryRegistry {
public:
    explicit FileRegistry(std::string path) : path_(std::move(path)) {}

    Status Load()
    {
        SG_TRY(LockStore(path_, &lock_));  // one process at a time (see LockStore)
        Bytes data;
        const Status st = ReadWholeFile(path_, &data);
        if (st == SG_NOT_FOUND) return OkStatus();  // new registry
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
        if (!r.U32(&magic).ok() || magic != kRegistryMagic) return SG_STORAGE_ERROR;
        if (!r.U16(&version).ok() || version != kRegistryVersion) return SG_STORAGE_ERROR;
        if (!r.U32(&count).ok() || count > kMaxRecords) return SG_STORAGE_ERROR;
        for (uint32_t i = 0; i < count; ++i) {
            ClientRecord rec;
            uint8_t status = 0;
            ByteView product;
            ByteView license;
            if (!r.Fixed(&rec.installation_id).ok() || !r.Fixed(&rec.public_key).ok() || !r.U8(&rec.key_algorithm).ok() ||
                !r.U8(&status).ok() || !r.Vec16(0, proto::kMaxProductIdLength, &product).ok() ||
                !r.Vec16(0, proto::kMaxLicenseIdLength, &license).ok() || !r.U64(&rec.created_at_ms).ok()) {
                return SG_STORAGE_ERROR;
            }
            rec.status = static_cast<ClientStatus>(status);
            rec.product_id.assign(reinterpret_cast<const char*>(product.data()), product.size());
            rec.license_id.assign(reinterpret_cast<const char*>(license.data()), license.size());
            if (!Validate(rec).ok() || records_.count(rec.installation_id) != 0) return SG_STORAGE_ERROR;
            records_[rec.installation_id] = rec;
        }
        uint32_t token_count = 0;
        if (!r.U32(&token_count).ok() || token_count > kMaxRecords) return SG_STORAGE_ERROR;
        for (uint32_t i = 0; i < token_count; ++i) {
            proto::TokenId id;
            uint64_t expires = 0;
            if (!r.Fixed(&id).ok() || !r.U64(&expires).ok()) return SG_STORAGE_ERROR;
            tokens_[id] = TokenEntry{expires};
        }
        return r.ExpectEnd().ok() ? OkStatus() : Status(SG_STORAGE_ERROR);
    }

    Status PersistLocked() override
    {
        Bytes out;
        ser::Writer w(&out);
        w.U32(kRegistryMagic);
        w.U16(kRegistryVersion);
        w.U32(static_cast<uint32_t>(records_.size()));
        for (const auto& entry : records_) {
            const ClientRecord& rec = entry.second;
            w.Raw(rec.installation_id);
            w.Raw(rec.public_key);
            w.U8(rec.key_algorithm);
            w.U8(static_cast<uint8_t>(rec.status));
            SG_TRY(w.Vec16(ser::AsBytes(rec.product_id)));
            SG_TRY(w.Vec16(ser::AsBytes(rec.license_id)));
            w.U64(rec.created_at_ms);
        }
        w.U32(static_cast<uint32_t>(tokens_.size()));
        for (const auto& entry : tokens_) {
            w.Raw(entry.first);
            w.U64(entry.second.expires_at_ms);
        }
        return WriteFileAtomically(path_, out);
    }

    const std::string path_;
    std::unique_ptr<StoreLock> lock_;
};

}  // namespace

std::unique_ptr<IClientRegistry> CreateMemoryClientRegistry() { return std::make_unique<MemoryRegistry>(); }

Status CreateFileClientRegistry(const std::string& path, std::unique_ptr<IClientRegistry>* out)
{
    if (out == nullptr || path.empty()) return SG_INVALID_ARGUMENT;
    auto registry = std::make_unique<FileRegistry>(path);
    SG_TRY(registry->Load());
    *out = std::move(registry);
    return OkStatus();
}

}  // namespace sg::server
