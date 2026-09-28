#include "crypto/key_store.h"

#include "sockgate_common/protocol/transcript.h"

#include <map>
#include <mutex>

namespace sg::client {

const char* KeyStoreKindName(KeyStoreKind kind) noexcept
{
    switch (kind) {
    case KeyStoreKind::kMemory: return "memory";
    case KeyStoreKind::kFile: return "file";
    case KeyStoreKind::kCngSoftware: return "cng-software";
    case KeyStoreKind::kCngTpm: return "cng-tpm";
    case KeyStoreKind::kTpm2: return "tpm2";
    }
    return "unknown";
}

Status ValidateKeyName(const std::string& name)
{
    if (name.empty() || name.size() > 128) return SG_INVALID_ARGUMENT;
    if (name == "." || name == "..") return SG_INVALID_ARGUMENT;
    for (char c : name) {
        const bool ok = (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') || (c >= '0' && c <= '9') || c == '.' ||
                        c == '_' || c == '-';
        if (!ok) return SG_INVALID_ARGUMENT;
    }
    return OkStatus();
}

Status GetIdentity(IKeyStore& store, const std::string& name, IdentityInfo* out)
{
    if (out == nullptr) return SG_INVALID_ARGUMENT;
    SG_TRY(ValidateKeyName(name));
    SG_TRY(store.GetPublicKey(name, &out->public_key));
    SG_TRY(crypto::ValidateP256PublicKey(out->public_key));
    SG_TRY(proto::DeriveInstallationId(out->public_key, &out->installation_id));
    out->kind = store.Kind();
    out->hardware_backed = store.HardwareBacked();
    out->created = false;
    return OkStatus();
}

Status EnsureIdentity(IKeyStore& store, const std::string& name, IdentityInfo* out)
{
    if (out == nullptr) return SG_INVALID_ARGUMENT;
    SG_TRY(ValidateKeyName(name));
    Status st = GetIdentity(store, name, out);
    if (st.ok()) return st;
    if (st != SG_NOT_FOUND) return st;

    st = store.GenerateKeyPair(name);
    const bool created = st.ok();
    if (!st.ok() && st != SG_ALREADY_EXISTS) return st;  // ALREADY_EXISTS: lost a creation race
    SG_TRY(GetIdentity(store, name, out));
    out->created = created;
    return OkStatus();
}

namespace {

class MemoryKeyStore final : public IKeyStore {
public:
    KeyStoreKind Kind() const noexcept override { return KeyStoreKind::kMemory; }
    bool HardwareBacked() const noexcept override { return false; }

    Status GenerateKeyPair(const std::string& name) override
    {
        SG_TRY(ValidateKeyName(name));
        std::unique_ptr<crypto::SoftwareP256Key> key;
        SG_TRY(crypto::SoftwareP256Key::Generate(&key));
        std::lock_guard<std::mutex> lock(mutex_);
        if (keys_.count(name) != 0) return SG_ALREADY_EXISTS;
        keys_[name] = std::move(key);
        return OkStatus();
    }

    Status GetPublicKey(const std::string& name, crypto::P256PublicKey* out) override
    {
        if (out == nullptr) return SG_INVALID_ARGUMENT;
        std::lock_guard<std::mutex> lock(mutex_);
        auto it = keys_.find(name);
        if (it == keys_.end()) return SG_NOT_FOUND;
        return it->second->PublicKey(out);
    }

    Status Sign(const std::string& name, ByteView message, crypto::P256Signature* out) override
    {
        if (out == nullptr) return SG_INVALID_ARGUMENT;
        std::lock_guard<std::mutex> lock(mutex_);
        auto it = keys_.find(name);
        if (it == keys_.end()) return SG_NOT_FOUND;
        return it->second->Sign(message, out);
    }

    Status DeleteKey(const std::string& name) override
    {
        std::lock_guard<std::mutex> lock(mutex_);
        return keys_.erase(name) != 0 ? OkStatus() : Status(SG_NOT_FOUND);
    }

private:
    std::mutex mutex_;
    std::map<std::string, std::unique_ptr<crypto::SoftwareP256Key>> keys_;
};

}  // namespace

std::unique_ptr<IKeyStore> CreateMemoryKeyStore() { return std::make_unique<MemoryKeyStore>(); }

}  // namespace sg::client
