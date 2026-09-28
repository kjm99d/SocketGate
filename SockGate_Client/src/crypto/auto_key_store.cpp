// AUTO key store: an ordered list of stores, strongest first.
//
// An existing key is used wherever it lives, so an identity never moves
// between stores. New keys are created in the first store that supports key
// creation (only SG_NOT_SUPPORTED moves on to the next); any other error is
// reported instead of silently falling back to a weaker store.
//
// A store that is temporarily absent (TPM disabled, provider not available)
// cannot answer "not found" reliably, so each identity gets a locator file
// "<name>.sgref" recording the store that holds it:
//
//   u32 magic "SGRF" | u16 version (1) | u8 store kind | u8 reserved (0)
//
// Once recorded, only that store is asked. If it is not available AUTO fails
// with SG_KEYSTORE_ERROR, if it no longer has the key with SG_IDENTITY_LOST;
// never by creating a replacement identity. DeleteKey removes keys and
// locator (refused while the recorded store is unavailable, so a surviving
// key is not silently orphaned); ForceDeleteKey is the explicit way out.
#include "crypto/key_store.h"

#include "platform/key_file.h"

#include "sockgate_common/serialization/reader.h"
#include "sockgate_common/serialization/writer.h"

namespace sg::client {
namespace {

constexpr uint32_t kLocatorMagic = 0x53475246;  // "SGRF"
constexpr uint16_t kLocatorVersion = 1;

std::string LocatorFile(const std::string& name) { return name + ".sgref"; }

class AutoKeyStore final : public IKeyStore {
public:
    AutoKeyStore(std::vector<std::unique_ptr<IKeyStore>> stores, std::string dir)
        : stores_(std::move(stores)), dir_(std::move(dir))
    {
    }

    KeyStoreKind Kind() const noexcept override { return stores_.front()->Kind(); }
    bool HardwareBacked() const noexcept override { return stores_.front()->HardwareBacked(); }

    Status GenerateKeyPair(const std::string& name) override
    {
        SG_TRY(ValidateKeyName(name));
        IKeyStore* existing = nullptr;
        crypto::P256PublicKey key;
        const Status found = Locate(name, &existing, &key);
        if (found.ok()) return SG_ALREADY_EXISTS;
        if (found != SG_NOT_FOUND) return found;
        for (const auto& store : stores_) {
            const Status st = store->GenerateKeyPair(name);
            if (st == SG_NOT_SUPPORTED) continue;
            SG_TRY(st);
            // Without the locator the silent-replacement protection is gone:
            // report it; the key exists and the next lookup records it.
            return RecordLocator(name, store->Kind());
        }
        return SG_NOT_SUPPORTED;
    }

    Status GetPublicKey(const std::string& name, crypto::P256PublicKey* out) override
    {
        if (out == nullptr) return SG_INVALID_ARGUMENT;
        IKeyStore* store = nullptr;
        return Locate(name, &store, out);
    }

    Status Sign(const std::string& name, ByteView message, crypto::P256Signature* out) override
    {
        IKeyStore* store = nullptr;
        crypto::P256PublicKey key;
        SG_TRY(Locate(name, &store, &key));
        return store->Sign(name, message, out);
    }

    Status DeleteKey(const std::string& name) override
    {
        SG_TRY(ValidateKeyName(name));
        KeyStoreKind recorded = KeyStoreKind::kMemory;
        const Status locator = ReadLocator(name, &recorded);
        if (!locator.ok() && locator != SG_NOT_FOUND) return locator;
        if (!locator.ok()) return DeleteFromStores(name, /*tolerate_errors=*/false);
        // Recorded identity: only its store matters (others cannot block it).
        IKeyStore* store = StoreOfKind(recorded);
        if (store == nullptr) return SG_KEYSTORE_ERROR;  // cannot reach its key: refuse, see ForceDeleteKey
        const Status st = store->DeleteKey(name);
        if (!st.ok() && st != SG_NOT_FOUND) return st;
        return platform::DeleteKeyFile(dir_, LocatorFile(name));
    }

    // Forgets the identity even if its store is unavailable or failing: the
    // locator is always removed; keys in failing stores may survive.
    Status ForceDeleteKey(const std::string& name) override
    {
        SG_TRY(ValidateKeyName(name));
        const Status keys = DeleteFromStores(name, /*tolerate_errors=*/true);
        const Status locator = platform::DeleteKeyFile(dir_, LocatorFile(name));
        if (!locator.ok() && locator != SG_NOT_FOUND) return locator;
        return locator.ok() ? OkStatus() : keys;
    }

    Status Describe(const std::string& name, crypto::P256PublicKey* public_key, KeyStoreKind* kind,
                    bool* hardware_backed) override
    {
        if (public_key == nullptr || kind == nullptr || hardware_backed == nullptr) return SG_INVALID_ARGUMENT;
        IKeyStore* store = nullptr;
        SG_TRY(Locate(name, &store, public_key));
        *kind = store->Kind();
        *hardware_backed = store->HardwareBacked();
        return OkStatus();
    }

private:
    // Deletes `name` from every store (duplicates left by creation races).
    Status DeleteFromStores(const std::string& name, bool tolerate_errors)
    {
        bool deleted = false;
        for (const auto& store : stores_) {
            const Status st = store->DeleteKey(name);
            if (st.ok()) {
                deleted = true;
            } else if (st != SG_NOT_FOUND && !tolerate_errors) {
                return st;
            }
        }
        return deleted ? OkStatus() : Status(SG_NOT_FOUND);
    }

    IKeyStore* StoreOfKind(KeyStoreKind kind) const
    {
        for (const auto& store : stores_) {
            if (store->Kind() == kind) return store.get();
        }
        return nullptr;
    }

    // Finds the store holding `name`. Only SG_NOT_FOUND means "absent".
    Status Locate(const std::string& name, IKeyStore** out, crypto::P256PublicKey* key)
    {
        SG_TRY(ValidateKeyName(name));
        KeyStoreKind recorded = KeyStoreKind::kMemory;
        const Status locator = ReadLocator(name, &recorded);
        if (locator.ok()) {
            // Only the recorded store counts: other stores cannot stand in
            // for it, and their failures do not affect this identity.
            IKeyStore* store = StoreOfKind(recorded);
            if (store == nullptr) return SG_KEYSTORE_ERROR;  // unavailable right now
            const Status st = store->GetPublicKey(name, key);
            if (st == SG_NOT_FOUND) return SG_IDENTITY_LOST;
            SG_TRY(st);
            *out = store;
            return OkStatus();
        }
        if (locator != SG_NOT_FOUND) return locator;
        // No locator: a new identity, or one created before locators existed.
        for (const auto& store : stores_) {
            const Status st = store->GetPublicKey(name, key);
            if (st == SG_NOT_FOUND) continue;
            SG_TRY(st);
            SG_TRY(RecordLocator(name, store->Kind()));
            *out = store.get();
            return OkStatus();
        }
        return SG_NOT_FOUND;
    }

    Status ReadLocator(const std::string& name, KeyStoreKind* kind)
    {
        SecureBytes data;
        SG_TRY(platform::ReadKeyFile(dir_, LocatorFile(name), &data));
        ser::Reader r(data);
        uint32_t magic = 0;
        uint16_t version = 0;
        uint8_t value = 0;
        uint8_t reserved = 1;
        if (!r.U32(&magic).ok() || magic != kLocatorMagic || !r.U16(&version).ok() || version != kLocatorVersion ||
            !r.U8(&value).ok() || !r.U8(&reserved).ok() || reserved != 0 || !r.ExpectEnd().ok() ||
            value < static_cast<uint8_t>(KeyStoreKind::kFile) || value > static_cast<uint8_t>(KeyStoreKind::kTpm2)) {
            return SG_KEYSTORE_ERROR;
        }
        *kind = static_cast<KeyStoreKind>(value);
        return OkStatus();
    }

    Status RecordLocator(const std::string& name, KeyStoreKind kind)
    {
        Bytes data;
        ser::Writer w(&data);
        w.U32(kLocatorMagic);
        w.U16(kLocatorVersion);
        w.U8(static_cast<uint8_t>(kind));
        w.U8(0);
        const Status st = platform::CreateKeyFile(dir_, LocatorFile(name), data);
        if (st != SG_ALREADY_EXISTS) return st;
        // A concurrent creator recorded it first: it must name the same store.
        KeyStoreKind recorded = KeyStoreKind::kMemory;
        SG_TRY(ReadLocator(name, &recorded));
        return recorded == kind ? OkStatus() : Status(SG_KEYSTORE_ERROR);
    }

    std::vector<std::unique_ptr<IKeyStore>> stores_;
    const std::string dir_;
};

}  // namespace

Status CreateAutoKeyStore(std::vector<std::unique_ptr<IKeyStore>> stores, const std::string& locator_directory,
                          std::unique_ptr<IKeyStore>* out)
{
    if (out == nullptr || stores.empty()) return SG_INVALID_ARGUMENT;
    for (const auto& store : stores) {
        if (store == nullptr || store->Kind() == KeyStoreKind::kMemory) return SG_INVALID_ARGUMENT;
    }
    std::string dir = locator_directory;
    if (dir.empty()) SG_TRY(platform::DefaultKeyDirectory(&dir));
    SG_TRY(platform::PrepareKeyDirectory(dir));
    *out = std::make_unique<AutoKeyStore>(std::move(stores), std::move(dir));
    return OkStatus();
}

}  // namespace sg::client
