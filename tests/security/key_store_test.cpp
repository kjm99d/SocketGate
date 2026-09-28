// Phase 8: platform key stores. Private keys must stay inside their store,
// persistent stores must refuse tampered / foreign / linked files, and AUTO
// must never silently create a new identity in a weaker store.
#include "sg_test.h"

#include "crypto/key_store.h"
#include "crypto/key_store_factory.h"
#include "platform/key_file.h"

#include "sockgate_common/core/clock.h"
#include "sockgate_common/crypto/crypto.h"

#include <sockgate/config.h>

#include <algorithm>
#include <cstdio>
#include <cstdlib>
#include <filesystem>
#include <functional>
#include <fstream>
#include <iterator>
#include <string>
#include <thread>
#include <vector>

#ifdef _WIN32
#include <windows.h>
#include <aclapi.h>
#include <ncrypt.h>
#else
#include <sys/stat.h>
#include <unistd.h>
#endif

using namespace sg;
using namespace sg::client;
namespace fs = std::filesystem;

namespace {

// SOCKGATE_REQUIRE_TPM=1 turns "no TPM here" into a failure (CI machines
// that are supposed to have a TPM / swtpm must not silently skip it).
[[maybe_unused]] bool RequireTpm()
{
#ifdef _MSC_VER
    char* value = nullptr;
    size_t len = 0;
    const bool set = _dupenv_s(&value, &len, "SOCKGATE_REQUIRE_TPM") == 0 && value != nullptr && value[0] == '1';
    std::free(value);
    return set;
#else
    const char* value = std::getenv("SOCKGATE_REQUIRE_TPM");
    return value != nullptr && value[0] == '1';
#endif
}

// Unique per run so concurrent test processes never share keys.
std::string UniqueName(const char* base)
{
    uint8_t rnd[6];
    SG_ASSERT_OK(crypto::RandomBytes(rnd, sizeof(rnd)));
    return std::string("sgtest-") + base + "-" + ToHex(ByteView(rnd, sizeof(rnd)));
}

class TempDir {
public:
    TempDir() : path_(fs::temp_directory_path() / UniqueName("keys")) {}
    ~TempDir()
    {
        std::error_code ec;
        fs::remove_all(path_, ec);
    }
    std::string str() const { return path_.u8string(); }
    fs::path path() const { return path_; }

private:
    fs::path path_;
};

Bytes ReadFileBytes(const fs::path& p)
{
    std::ifstream f(p, std::ios::binary);
    return Bytes(std::istreambuf_iterator<char>(f), std::istreambuf_iterator<char>());
}

void WriteFileBytes(const fs::path& p, const Bytes& data)
{
    std::ofstream f(p, std::ios::binary | std::ios::trunc);
    f.write(reinterpret_cast<const char*>(data.data()), static_cast<std::streamsize>(data.size()));
}

// Signs with the store and verifies with the public key it reports.
void ExpectWorkingKey(IKeyStore& store, const std::string& name)
{
    crypto::P256PublicKey pub;
    SG_ASSERT_OK(store.GetPublicKey(name, &pub));
    const Bytes message = {'s', 'i', 'g', 'n', ' ', 'm', 'e'};
    crypto::P256Signature sig;
    SG_ASSERT_OK(store.Sign(name, message, &sig));
    SG_EXPECT_OK(crypto::VerifyP256(pub, message, sig));
    Bytes other = message;
    other[0] ^= 1;
    SG_EXPECT(!crypto::VerifyP256(pub, other, sig).ok());
}

// Wraps a memory store but reports another kind; can simulate failures.
class FakeStore final : public IKeyStore {
public:
    FakeStore(KeyStoreKind kind, bool hardware) : kind_(kind), hardware_(hardware) {}
    KeyStoreKind Kind() const noexcept override { return kind_; }
    bool HardwareBacked() const noexcept override { return hardware_; }
    Status GenerateKeyPair(const std::string& name) override
    {
        ++generate_calls;
        return generate_status.ok() ? inner_->GenerateKeyPair(name) : generate_status;
    }
    Status GetPublicKey(const std::string& name, crypto::P256PublicKey* out) override
    {
        return lookup_status.ok() ? inner_->GetPublicKey(name, out) : lookup_status;
    }
    Status Sign(const std::string& name, ByteView m, crypto::P256Signature* out) override
    {
        return lookup_status.ok() ? inner_->Sign(name, m, out) : lookup_status;
    }
    Status DeleteKey(const std::string& name) override
    {
        return delete_status.ok() ? inner_->DeleteKey(name) : delete_status;
    }

    Status generate_status = OkStatus();
    Status lookup_status = OkStatus();
    Status delete_status = OkStatus();
    int generate_calls = 0;

private:
    KeyStoreKind kind_;
    bool hardware_;
    std::unique_ptr<IKeyStore> inner_ = CreateMemoryKeyStore();
};

}  // namespace

SG_TEST(FileKeyStore, PersistentIdentity)
{
    TempDir dir;
    const std::string name = UniqueName("id");
    IdentityInfo first;
    {
        std::unique_ptr<IKeyStore> store;
        SG_ASSERT_OK(CreateFileKeyStore(dir.str(), &store));
        SG_ASSERT_OK(EnsureIdentity(*store, name, &first));
        SG_EXPECT(first.created);
        SG_EXPECT(first.kind == KeyStoreKind::kFile);
        SG_EXPECT(!first.hardware_backed);
        ExpectWorkingKey(*store, name);
        SG_EXPECT_STATUS(store->GenerateKeyPair(name), SG_ALREADY_EXISTS);
    }
    {
        // A new store instance (as after a restart) finds the same key.
        std::unique_ptr<IKeyStore> store;
        SG_ASSERT_OK(CreateFileKeyStore(dir.str(), &store));
        IdentityInfo again;
        SG_ASSERT_OK(EnsureIdentity(*store, name, &again));
        SG_EXPECT(!again.created);
        SG_EXPECT(again.installation_id == first.installation_id);
        ExpectWorkingKey(*store, name);

        // One file per key, no temporaries left behind.
        size_t files = 0;
        for (const auto& entry : fs::directory_iterator(dir.path())) {
            ++files;
            SG_EXPECT_EQ(entry.path().filename().u8string(), name + ".sgkey");
        }
        SG_EXPECT_EQ(files, size_t{1});

        SG_ASSERT_OK(store->DeleteKey(name));
        crypto::P256PublicKey pub;
        SG_EXPECT_STATUS(store->GetPublicKey(name, &pub), SG_NOT_FOUND);
        SG_EXPECT_STATUS(store->DeleteKey(name), SG_NOT_FOUND);
        SG_EXPECT(fs::is_empty(dir.path()));
    }
    // Names are validated before touching the file system.
    std::unique_ptr<IKeyStore> store;
    SG_ASSERT_OK(CreateFileKeyStore(dir.str(), &store));
    for (const char* bad : {"", "..", ".hidden", "a/b", "a\\b", "x:y", "name with space", "CON", "nul.key",
                            "Com1", "LPT9.x", "aux"}) {
        SG_EXPECT_STATUS(store->GenerateKeyPair(bad), SG_INVALID_ARGUMENT);
    }
}

SG_TEST(FileKeyStore, RemovedDirectoryIsRecreated)
{
    TempDir dir;
    const std::string name = UniqueName("gone");
    std::unique_ptr<IKeyStore> store;
    SG_ASSERT_OK(CreateFileKeyStore(dir.str(), &store));
    SG_ASSERT_OK(store->GenerateKeyPair(name));
    fs::remove_all(dir.path());
    crypto::P256PublicKey pub;
    SG_EXPECT_STATUS(store->GetPublicKey(name, &pub), SG_NOT_FOUND);
    SG_EXPECT_STATUS(store->DeleteKey(name), SG_NOT_FOUND);
    IdentityInfo id;
    SG_ASSERT_OK(EnsureIdentity(*store, name, &id));
    SG_EXPECT(id.created);
    ExpectWorkingKey(*store, name);
}

SG_TEST(FileKeyStore, TamperedFilesAreRefused)
{
    TempDir dir;
    const std::string name = UniqueName("tamper");
    std::unique_ptr<IKeyStore> store;
    SG_ASSERT_OK(CreateFileKeyStore(dir.str(), &store));
    SG_ASSERT_OK(store->GenerateKeyPair(name));
    const fs::path file = dir.path() / (name + ".sgkey");
    const Bytes original = ReadFileBytes(file);
    SG_ASSERT(original.size() > 80);
    crypto::P256PublicKey original_pub;
    SG_ASSERT_OK(store->GetPublicKey(name, &original_pub));

    auto install = [&](const Bytes& content) {
        fs::remove(file);
        WriteFileBytes(file, content);
#ifndef _WIN32
        fs::permissions(file, fs::perms::owner_read | fs::perms::owner_write);
#endif
    };
    // Structural damage must be refused.
    auto expect_refused = [&](const Bytes& content, const char* what) {
        install(content);
        crypto::P256PublicKey pub;
        const Status st = store->GetPublicKey(name, &pub);
        if (st.ok()) std::fprintf(stderr, "    tampering not detected: %s\n", what);
        SG_EXPECT_STATUS(st, SG_KEYSTORE_ERROR);
    };
    // Inside the protected blob a change may be refused or be without effect
    // (bytes of the DPAPI envelope its MAC does not cover), but it must never
    // yield a different key.
    size_t refused = 0;
    size_t no_effect = 0;
    auto expect_no_other_key = [&](const Bytes& content) {
        install(content);
        crypto::P256PublicKey pub;
        const Status st = store->GetPublicKey(name, &pub);
        if (!st.ok()) {
            SG_EXPECT_STATUS(st, SG_KEYSTORE_ERROR);
            ++refused;
            return;
        }
        SG_EXPECT(pub == original_pub);
        crypto::P256Signature sig;
        const Bytes message = {'x'};
        SG_ASSERT_OK(store->Sign(name, message, &sig));
        SG_EXPECT_OK(crypto::VerifyP256(original_pub, message, sig));
        ++no_effect;
    };
    Bytes b = original;
    b[0] ^= 1;
    expect_refused(b, "magic");
    b = original;
    b[6] ^= 0x03;
    expect_refused(b, "protection id");
    b = original;
    b[8 + 10] ^= 0x01;
    expect_refused(b, "stored public key");
    b = original;
    b.resize(b.size() - 1);
    expect_refused(b, "truncated");
    b = original;
    b.push_back(0);
    expect_refused(b, "trailing byte");
    // Bytes of the protected private key blob.
    const size_t blob_start = 4 + 2 + 1 + 1 + 65 + 4;
    for (size_t i = blob_start; i < original.size(); i += 3) {
        b = original;
        b[i] ^= 0x5A;
        expect_no_other_key(b);
    }
    std::fprintf(stderr, "    blob tampering: %zu refused, %zu without effect\n", refused, no_effect);
    SG_EXPECT(refused > no_effect);
    // The untouched file still works.
    fs::remove(file);
    WriteFileBytes(file, original);
#ifndef _WIN32
    fs::permissions(file, fs::perms::owner_read | fs::perms::owner_write);
#endif
    ExpectWorkingKey(*store, name);
}

SG_TEST(FileKeyStore, LinksAreRefused)
{
    TempDir dir;
    const std::string name = UniqueName("link");
    std::unique_ptr<IKeyStore> store;
    SG_ASSERT_OK(CreateFileKeyStore(dir.str(), &store));
    SG_ASSERT_OK(store->GenerateKeyPair(name));
    const fs::path file = dir.path() / (name + ".sgkey");

    // A second hard link (e.g. planted elsewhere by another account).
    const fs::path alias = dir.path() / "alias.bin";
    std::error_code ec;
    fs::create_hard_link(file, alias, ec);
    SG_ASSERT(!ec);
    crypto::P256PublicKey pub;
    SG_EXPECT_STATUS(store->GetPublicKey(name, &pub), SG_KEYSTORE_ERROR);
    SG_EXPECT_STATUS(store->DeleteKey(name), SG_KEYSTORE_ERROR);
    fs::remove(alias);
    SG_EXPECT_OK(store->GetPublicKey(name, &pub));

#ifndef _WIN32
    // A symlink in place of the key file is never followed.
    const std::string other = UniqueName("target");
    SG_ASSERT_OK(store->GenerateKeyPair(other));
    fs::remove(file);
    fs::create_symlink(dir.path() / (other + ".sgkey"), file);
    SG_EXPECT_STATUS(store->GetPublicKey(name, &pub), SG_KEYSTORE_ERROR);
#endif
}

#ifdef _WIN32
SG_TEST(FileKeyStore, WindowsProtection)
{
    TempDir dir;
    const std::string a = UniqueName("a");
    const std::string b = UniqueName("b");
    std::unique_ptr<IKeyStore> store;
    SG_ASSERT_OK(CreateFileKeyStore((dir.path() / "nested" / "keys").u8string(), &store));
    SG_ASSERT_OK(store->GenerateKeyPair(a));
    SG_ASSERT_OK(store->GenerateKeyPair(b));
    const fs::path keys = dir.path() / "nested" / "keys";

    // DPAPI entropy binds a blob to its key name: swapping files fails.
    fs::copy_file(keys / (a + ".sgkey"), keys / (b + ".sgkey"), fs::copy_options::overwrite_existing);
    crypto::P256PublicKey pub;
    SG_EXPECT_STATUS(store->GetPublicKey(b, &pub), SG_KEYSTORE_ERROR);
    SG_EXPECT_OK(store->GetPublicKey(a, &pub));

    // The PKCS#8 never appears in plaintext on disk.
    const Bytes content = ReadFileBytes(keys / (a + ".sgkey"));
    const uint8_t ec_oid[] = {0x2A, 0x86, 0x48, 0xCE, 0x3D, 0x02, 0x01};  // id-ecPublicKey
    SG_EXPECT(std::search(content.begin(), content.end(), std::begin(ec_oid), std::end(ec_oid)) == content.end());

    // Created directories carry a protected DACL (no inherited access).
    PSECURITY_DESCRIPTOR sd = nullptr;
    PACL dacl = nullptr;
    SG_ASSERT(GetNamedSecurityInfoW(keys.wstring().c_str(), SE_FILE_OBJECT, DACL_SECURITY_INFORMATION, nullptr,
                                    nullptr, &dacl, nullptr, &sd) == ERROR_SUCCESS);
    SECURITY_DESCRIPTOR_CONTROL control = 0;
    DWORD revision = 0;
    SG_EXPECT(GetSecurityDescriptorControl(sd, &control, &revision));
    SG_EXPECT((control & SE_DACL_PROTECTED) != 0);
    SG_EXPECT(dacl != nullptr && dacl->AceCount == 2);
    LocalFree(sd);
}
#else
SG_TEST(FileKeyStore, PosixPermissions)
{
    TempDir dir;
    const std::string name = UniqueName("perm");
    std::unique_ptr<IKeyStore> store;
    SG_ASSERT_OK(CreateFileKeyStore(dir.str(), &store));
    SG_ASSERT_OK(store->GenerateKeyPair(name));
    const fs::path file = dir.path() / (name + ".sgkey");
    struct stat st;
    SG_ASSERT(::stat(file.c_str(), &st) == 0);
    SG_EXPECT_EQ(static_cast<unsigned>(st.st_mode & 0777), 0600u);
    SG_ASSERT(::stat(dir.path().c_str(), &st) == 0);
    SG_EXPECT_EQ(static_cast<unsigned>(st.st_mode & 0077), 0u);

    // Readable by others: refused, even though the content is intact.
    crypto::P256PublicKey pub;
    SG_ASSERT(::chmod(file.c_str(), 0640) == 0);
    SG_EXPECT_STATUS(store->GetPublicKey(name, &pub), SG_KEYSTORE_ERROR);
    SG_ASSERT(::chmod(file.c_str(), 0600) == 0);
    SG_EXPECT_OK(store->GetPublicKey(name, &pub));

    // A directory others can write to is refused.
    SG_ASSERT(::chmod(dir.path().c_str(), 0777) == 0);
    SG_EXPECT_STATUS(store->GetPublicKey(name, &pub), SG_KEYSTORE_ERROR);
    std::unique_ptr<IKeyStore> other;
    SG_EXPECT_STATUS(CreateFileKeyStore(dir.str(), &other), SG_KEYSTORE_ERROR);
    SG_ASSERT(::chmod(dir.path().c_str(), 0700) == 0);

    // The store directory itself must not be a symlink.
    const fs::path link = dir.path().parent_path() / (dir.path().filename().u8string() + "-link");
    fs::create_directory_symlink(dir.path(), link);
    SG_EXPECT_STATUS(CreateFileKeyStore(link.u8string(), &other), SG_KEYSTORE_ERROR);
    fs::remove(link);
}
#endif

// Creators racing on the same names (independent store instances, as in
// separate processes: the file system is the only arbiter) must all end up
// with one identity per name and never see an error.
void RaceCreators(const std::function<Status(std::unique_ptr<IKeyStore>*)>& open_store, int rounds)
{
    constexpr size_t kThreads = 6;
    for (int round = 0; round < rounds; ++round) {
        const std::string name = UniqueName("race");
        std::vector<IdentityInfo> ids(kThreads);
        std::vector<Status> results(kThreads, OkStatus());
        std::vector<std::thread> threads;
        for (size_t t = 0; t < kThreads; ++t) {
            threads.emplace_back([&, t]() {
                std::unique_ptr<IKeyStore> store;
                results[t] = open_store(&store);
                if (results[t].ok()) results[t] = EnsureIdentity(*store, name, &ids[t]);
            });
        }
        for (auto& th : threads) th.join();
        int created = 0;
        for (size_t t = 0; t < kThreads; ++t) {
            SG_EXPECT_OK(results[t]);
            if (!results[t].ok()) continue;
            created += ids[t].created ? 1 : 0;
            SG_EXPECT(ids[t].installation_id == ids[0].installation_id);
        }
        SG_EXPECT_EQ(created, 1);
        std::unique_ptr<IKeyStore> store;
        SG_ASSERT_OK(open_store(&store));
        SG_EXPECT_OK(store->DeleteKey(name));
    }
}

SG_TEST(FileKeyStore, ConcurrentCreationYieldsOneIdentity)
{
    TempDir dir;
    RaceCreators([&](std::unique_ptr<IKeyStore>* out) { return CreateFileKeyStore(dir.str(), out); }, 20);
    // No temporaries left behind.
    for (const auto& entry : fs::directory_iterator(dir.path())) {
        std::fprintf(stderr, "    leftover: %s\n", entry.path().filename().u8string().c_str());
        SG_EXPECT(false);
    }
}

SG_TEST(AutoKeyStore, ConcurrentCreationYieldsOneIdentity)
{
    TempDir dir;
    RaceCreators(
        [&](std::unique_ptr<IKeyStore>* out) -> Status {
            std::vector<std::unique_ptr<IKeyStore>> stores;
            std::unique_ptr<IKeyStore> file;
            SG_TRY(CreateFileKeyStore(dir.str(), &file));
            stores.push_back(std::move(file));
            return CreateAutoKeyStore(std::move(stores), dir.str(), out);
        },
        10);
}

SG_TEST(AutoKeyStore, CreatesInStrongestSupportingStore)
{
    auto tpm = std::make_unique<FakeStore>(KeyStoreKind::kCngTpm, true);
    auto soft = std::make_unique<FakeStore>(KeyStoreKind::kCngSoftware, false);
    FakeStore* tpm_raw = tpm.get();
    FakeStore* soft_raw = soft.get();
    tpm_raw->generate_status = SG_NOT_SUPPORTED;  // e.g. TPM refuses ECC
    std::vector<std::unique_ptr<IKeyStore>> stores;
    stores.push_back(std::move(tpm));
    stores.push_back(std::move(soft));
    TempDir dir;
    std::unique_ptr<IKeyStore> autostore;
    SG_ASSERT_OK(CreateAutoKeyStore(std::move(stores), dir.str(), &autostore));

    IdentityInfo id;
    SG_ASSERT_OK(EnsureIdentity(*autostore, "app", &id));
    SG_EXPECT(id.created);
    SG_EXPECT(id.kind == KeyStoreKind::kCngSoftware);
    SG_EXPECT(!id.hardware_backed);
    ExpectWorkingKey(*autostore, "app");

    // Once the TPM works, the existing identity stays where it is.
    tpm_raw->generate_status = OkStatus();
    IdentityInfo again;
    SG_ASSERT_OK(EnsureIdentity(*autostore, "app", &again));
    SG_EXPECT(!again.created);
    SG_EXPECT(again.installation_id == id.installation_id);
    SG_EXPECT_EQ(tpm_raw->generate_calls, 1);
    SG_EXPECT_STATUS(autostore->GenerateKeyPair("app"), SG_ALREADY_EXISTS);

    // New identities go to the TPM now.
    SG_ASSERT_OK(EnsureIdentity(*autostore, "app2", &id));
    SG_EXPECT(id.kind == KeyStoreKind::kCngTpm);
    SG_EXPECT(id.hardware_backed);
    SG_EXPECT_EQ(soft_raw->generate_calls, 1);

    SG_ASSERT_OK(autostore->DeleteKey("app"));
    SG_EXPECT_STATUS(autostore->DeleteKey("app"), SG_NOT_FOUND);
}

SG_TEST(AutoKeyStore, StoreFailuresAreNotAbsentKeys)
{
    auto tpm = std::make_unique<FakeStore>(KeyStoreKind::kCngTpm, true);
    auto soft = std::make_unique<FakeStore>(KeyStoreKind::kCngSoftware, false);
    FakeStore* tpm_raw = tpm.get();
    FakeStore* soft_raw = soft.get();
    std::vector<std::unique_ptr<IKeyStore>> stores;
    stores.push_back(std::move(tpm));
    stores.push_back(std::move(soft));
    TempDir dir;
    std::unique_ptr<IKeyStore> autostore;
    SG_ASSERT_OK(CreateAutoKeyStore(std::move(stores), dir.str(), &autostore));
    IdentityInfo id;
    SG_ASSERT_OK(EnsureIdentity(*autostore, "app", &id));
    SG_EXPECT(id.kind == KeyStoreKind::kCngTpm);

    // The TPM is temporarily failing: no new identity may appear elsewhere.
    tpm_raw->lookup_status = SG_KEYSTORE_ERROR;
    IdentityInfo during;
    SG_EXPECT_STATUS(EnsureIdentity(*autostore, "app", &during), SG_KEYSTORE_ERROR);
    SG_EXPECT_STATUS(EnsureIdentity(*autostore, "fresh", &during), SG_KEYSTORE_ERROR);
    SG_EXPECT_EQ(soft_raw->generate_calls, 0);
    crypto::P256Signature sig;
    SG_EXPECT_STATUS(autostore->Sign("app", Bytes{1}, &sig), SG_KEYSTORE_ERROR);
    // "Unsupported" from a lookup is not "absent" either.
    tpm_raw->lookup_status = SG_NOT_SUPPORTED;
    SG_EXPECT_STATUS(EnsureIdentity(*autostore, "fresh", &during), SG_NOT_SUPPORTED);
    SG_EXPECT_EQ(soft_raw->generate_calls, 0);

    tpm_raw->lookup_status = OkStatus();
    IdentityInfo after;
    SG_ASSERT_OK(EnsureIdentity(*autostore, "app", &after));
    SG_EXPECT(after.installation_id == id.installation_id);

    // A creation failure other than "unsupported" is reported, not skipped.
    tpm_raw->generate_status = SG_KEYSTORE_ERROR;
    SG_EXPECT_STATUS(EnsureIdentity(*autostore, "other", &during), SG_KEYSTORE_ERROR);
    SG_EXPECT_EQ(soft_raw->generate_calls, 0);

    // AUTO never includes process memory.
    std::vector<std::unique_ptr<IKeyStore>> with_memory;
    with_memory.push_back(CreateMemoryKeyStore());
    SG_EXPECT_STATUS(CreateAutoKeyStore(std::move(with_memory), dir.str(), &autostore), SG_INVALID_ARGUMENT);
    SG_EXPECT_STATUS(CreateAutoKeyStore({}, dir.str(), &autostore), SG_INVALID_ARGUMENT);
}

SG_TEST(AutoKeyStore, VanishedStoreDoesNotYieldANewIdentity)
{
    TempDir dir;
    IdentityInfo original;
    {
        std::vector<std::unique_ptr<IKeyStore>> stores;
        stores.push_back(std::make_unique<FakeStore>(KeyStoreKind::kCngTpm, true));
        stores.push_back(std::make_unique<FakeStore>(KeyStoreKind::kCngSoftware, false));
        std::unique_ptr<IKeyStore> autostore;
        SG_ASSERT_OK(CreateAutoKeyStore(std::move(stores), dir.str(), &autostore));
        SG_ASSERT_OK(EnsureIdentity(*autostore, "app", &original));
        SG_EXPECT(original.kind == KeyStoreKind::kCngTpm);
    }
    // Next start: the TPM provider is unavailable (fTPM off, TBS not running),
    // so the TPM store is not part of AUTO at all.
    auto soft = std::make_unique<FakeStore>(KeyStoreKind::kCngSoftware, false);
    FakeStore* soft_raw = soft.get();
    std::vector<std::unique_ptr<IKeyStore>> stores;
    stores.push_back(std::move(soft));
    std::unique_ptr<IKeyStore> degraded;
    SG_ASSERT_OK(CreateAutoKeyStore(std::move(stores), dir.str(), &degraded));
    IdentityInfo id;
    SG_EXPECT_STATUS(EnsureIdentity(*degraded, "app", &id), SG_KEYSTORE_ERROR);
    SG_EXPECT_STATUS(degraded->GenerateKeyPair("app"), SG_KEYSTORE_ERROR);
    SG_EXPECT_EQ(soft_raw->generate_calls, 0);

    // A key of the same name in another store is not the recorded identity.
    SG_ASSERT_OK(soft_raw->GenerateKeyPair("app"));
    crypto::P256PublicKey pub;
    SG_EXPECT_STATUS(degraded->GetPublicKey("app", &pub), SG_KEYSTORE_ERROR);

    // A plain delete cannot reach the TPM key and refuses (the key would
    // survive); forcing it is the explicit way out.
    SG_EXPECT_STATUS(degraded->DeleteKey("app"), SG_KEYSTORE_ERROR);
    SG_ASSERT_OK(degraded->ForceDeleteKey("app"));
    SG_ASSERT_OK(EnsureIdentity(*degraded, "app", &id));
    SG_EXPECT(id.created);
    SG_EXPECT(id.kind == KeyStoreKind::kCngSoftware);
    SG_EXPECT(!(id.installation_id == original.installation_id));

    // Corrupt locators are errors, not "absent".
    const fs::path locator = dir.path() / "app.sgref";
    fs::remove(locator);
    WriteFileBytes(locator, Bytes{'S', 'G', 'R', 'F', 0, 1, 0x7F, 0});
#ifndef _WIN32
    fs::permissions(locator, fs::perms::owner_read | fs::perms::owner_write);
#endif
    SG_EXPECT_STATUS(degraded->GetPublicKey("app", &pub), SG_KEYSTORE_ERROR);
}

SG_TEST(AutoKeyStore, LostKeyIsReportedNotReplaced)
{
    TempDir dir;
    auto tpm = std::make_unique<FakeStore>(KeyStoreKind::kCngTpm, true);
    auto soft = std::make_unique<FakeStore>(KeyStoreKind::kCngSoftware, false);
    FakeStore* tpm_raw = tpm.get();
    FakeStore* soft_raw = soft.get();
    std::vector<std::unique_ptr<IKeyStore>> stores;
    stores.push_back(std::move(tpm));
    stores.push_back(std::move(soft));
    std::unique_ptr<IKeyStore> autostore;
    SG_ASSERT_OK(CreateAutoKeyStore(std::move(stores), dir.str(), &autostore));
    IdentityInfo id;
    SG_ASSERT_OK(EnsureIdentity(*autostore, "app", &id));

    // The TPM is cleared: the store works but no longer has the key.
    SG_ASSERT_OK(tpm_raw->DeleteKey("app"));
    IdentityInfo after;
    SG_EXPECT_STATUS(EnsureIdentity(*autostore, "app", &after), SG_IDENTITY_LOST);
    crypto::P256Signature sig;
    SG_EXPECT_STATUS(autostore->Sign("app", Bytes{1}, &sig), SG_IDENTITY_LOST);
    SG_EXPECT_EQ(soft_raw->generate_calls, 0);

    // The store is reachable, so a plain delete resets the identity.
    SG_ASSERT_OK(autostore->DeleteKey("app"));
    SG_ASSERT_OK(EnsureIdentity(*autostore, "app", &after));
    SG_EXPECT(after.created);
    SG_EXPECT(!(after.installation_id == id.installation_id));
}

SG_TEST(AutoKeyStore, OtherStoresCannotBreakARecordedIdentity)
{
    TempDir dir;
    auto tpm = std::make_unique<FakeStore>(KeyStoreKind::kCngTpm, true);
    auto soft = std::make_unique<FakeStore>(KeyStoreKind::kCngSoftware, false);
    FakeStore* tpm_raw = tpm.get();
    tpm_raw->generate_status = SG_NOT_SUPPORTED;
    std::vector<std::unique_ptr<IKeyStore>> stores;
    stores.push_back(std::move(tpm));
    stores.push_back(std::move(soft));
    std::unique_ptr<IKeyStore> autostore;
    SG_ASSERT_OK(CreateAutoKeyStore(std::move(stores), dir.str(), &autostore));
    IdentityInfo id;
    SG_ASSERT_OK(EnsureIdentity(*autostore, "app", &id));
    SG_EXPECT(id.kind == KeyStoreKind::kCngSoftware);

    // The TPM store starts failing: the software identity is unaffected,
    // including deleting it.
    tpm_raw->lookup_status = SG_KEYSTORE_ERROR;
    tpm_raw->delete_status = SG_KEYSTORE_ERROR;
    IdentityInfo again;
    SG_ASSERT_OK(EnsureIdentity(*autostore, "app", &again));
    SG_EXPECT(again.installation_id == id.installation_id);
    ExpectWorkingKey(*autostore, "app");
    SG_ASSERT_OK(autostore->DeleteKey("app"));
    SG_EXPECT(!fs::exists(dir.path() / "app.sgref"));
}

SG_TEST(AutoKeyStore, ForcedDeleteGetsPastBrokenStores)
{
    TempDir dir;
    auto tpm = std::make_unique<FakeStore>(KeyStoreKind::kCngTpm, true);
    FakeStore* tpm_raw = tpm.get();
    std::vector<std::unique_ptr<IKeyStore>> stores;
    stores.push_back(std::move(tpm));
    stores.push_back(std::make_unique<FakeStore>(KeyStoreKind::kCngSoftware, false));
    std::unique_ptr<IKeyStore> autostore;
    SG_ASSERT_OK(CreateAutoKeyStore(std::move(stores), dir.str(), &autostore));
    IdentityInfo id;
    SG_ASSERT_OK(EnsureIdentity(*autostore, "app", &id));

    tpm_raw->delete_status = SG_KEYSTORE_ERROR;  // the key cannot be removed
    SG_EXPECT_STATUS(autostore->DeleteKey("app"), SG_KEYSTORE_ERROR);
    SG_EXPECT(fs::exists(dir.path() / "app.sgref"));
    SG_ASSERT_OK(autostore->ForceDeleteKey("app"));
    SG_EXPECT(!fs::exists(dir.path() / "app.sgref"));

    // Documented: a key that survived a forced delete is adopted again if it
    // is still there when the identity is next used.
    IdentityInfo again;
    SG_ASSERT_OK(EnsureIdentity(*autostore, "app", &again));
    SG_EXPECT(!again.created);
    SG_EXPECT(again.installation_id == id.installation_id);
}

SG_TEST(KeyStoreFactory, Selection)
{
    TempDir dir;
    std::unique_ptr<IKeyStore> store;
    SG_ASSERT_OK(CreateKeyStore(SG_KEYSTORE_MEMORY, "", &store));
    SG_EXPECT(store->Kind() == KeyStoreKind::kMemory);
    SG_ASSERT_OK(CreateKeyStore(SG_KEYSTORE_FILE, dir.str(), &store));
    SG_EXPECT(store->Kind() == KeyStoreKind::kFile);
    SG_EXPECT_STATUS(CreateKeyStore(99, "", &store), SG_INVALID_ARGUMENT);
#ifndef SOCKGATE_WITH_TPM2
    SG_EXPECT_STATUS(CreateKeyStore(SG_KEYSTORE_TPM2, "", &store), SG_NOT_SUPPORTED);
#endif
#ifdef _WIN32
    SG_ASSERT_OK(CreateKeyStore(SG_KEYSTORE_CNG_SOFTWARE, "", &store));
    SG_EXPECT(store->Kind() == KeyStoreKind::kCngSoftware);
#else
    SG_EXPECT_STATUS(CreateKeyStore(SG_KEYSTORE_CNG_SOFTWARE, "", &store), SG_NOT_SUPPORTED);
    SG_EXPECT_STATUS(CreateKeyStore(SG_KEYSTORE_CNG_TPM, "", &store), SG_NOT_SUPPORTED);
#endif

    // AUTO: identities land in a platform store (never memory) and can be removed.
    SG_ASSERT_OK(CreateKeyStore(SG_KEYSTORE_AUTO, dir.str(), &store));
    const std::string name = UniqueName("auto");
    IdentityInfo id;
    SG_ASSERT_OK(EnsureIdentity(*store, name, &id));
    SG_EXPECT(id.kind != KeyStoreKind::kMemory);
    std::fprintf(stderr, "    AUTO selected %s\n", KeyStoreKindName(id.kind));
#ifdef _WIN32
    SG_EXPECT(id.kind == KeyStoreKind::kCngTpm || id.kind == KeyStoreKind::kCngSoftware);
    if (RequireTpm()) SG_EXPECT(id.kind == KeyStoreKind::kCngTpm);
#else
    SG_EXPECT(id.kind == KeyStoreKind::kFile || id.kind == KeyStoreKind::kTpm2);
#ifdef SOCKGATE_WITH_TPM2
    if (RequireTpm()) SG_EXPECT(id.kind == KeyStoreKind::kTpm2);
#endif
#endif
    ExpectWorkingKey(*store, name);
    SG_ASSERT_OK(store->DeleteKey(name));
}

#ifdef _WIN32
SG_TEST(CngKeyStore, SoftwareKeysAreNonExportable)
{
    std::unique_ptr<IKeyStore> store;
    SG_ASSERT_OK(CreateCngKeyStore(false, &store));
    const std::string name = UniqueName("cng");
    struct Cleanup {
        IKeyStore* s;
        std::string n;
        ~Cleanup() { s->DeleteKey(n).IgnoreError(); }
    } cleanup{store.get(), name};

    IdentityInfo id;
    SG_ASSERT_OK(EnsureIdentity(*store, name, &id));
    SG_EXPECT(id.created);
    SG_EXPECT(id.kind == KeyStoreKind::kCngSoftware);
    ExpectWorkingKey(*store, name);
    SG_EXPECT_STATUS(store->GenerateKeyPair(name), SG_ALREADY_EXISTS);

    // Persistent across store instances.
    std::unique_ptr<IKeyStore> again;
    SG_ASSERT_OK(CreateCngKeyStore(false, &again));
    IdentityInfo id2;
    SG_ASSERT_OK(GetIdentity(*again, name, &id2));
    SG_EXPECT(id2.installation_id == id.installation_id);

    // The private key cannot be exported in any form.
    NCRYPT_PROV_HANDLE prov = 0;
    SG_ASSERT(NCryptOpenStorageProvider(&prov, MS_KEY_STORAGE_PROVIDER, 0) == ERROR_SUCCESS);
    NCRYPT_KEY_HANDLE key = 0;
    const std::wstring wname = L"SockGate-" + std::wstring(name.begin(), name.end());
    SG_ASSERT(NCryptOpenKey(prov, &key, wname.c_str(), 0, NCRYPT_SILENT_FLAG) == ERROR_SUCCESS);
    for (LPCWSTR type : {BCRYPT_ECCPRIVATE_BLOB, NCRYPT_PKCS8_PRIVATE_KEY_BLOB}) {
        DWORD size = 0;
        const SECURITY_STATUS s = NCryptExportKey(key, 0, type, nullptr, nullptr, 0, &size, NCRYPT_SILENT_FLAG);
        std::vector<uint8_t> buf(size > 0 ? size : 1);
        const SECURITY_STATUS s2 = s == ERROR_SUCCESS
                                       ? NCryptExportKey(key, 0, type, nullptr, buf.data(), size, &size,
                                                         NCRYPT_SILENT_FLAG)
                                       : s;
        SG_EXPECT(s2 != ERROR_SUCCESS);
    }
    NCryptFreeObject(key);
    NCryptFreeObject(prov);

    SG_ASSERT_OK(store->DeleteKey(name));
    crypto::P256PublicKey pub;
    SG_EXPECT_STATUS(store->GetPublicKey(name, &pub), SG_NOT_FOUND);
}

SG_TEST(CngKeyStore, TpmWhenAvailable)
{
    std::unique_ptr<IKeyStore> store;
    const Status st = CreateCngKeyStore(true, &store);
    if (st == SG_NOT_SUPPORTED) {
        std::fprintf(stderr, "    Platform Crypto Provider unavailable: TPM keys not exercised\n");
        SG_EXPECT(!RequireTpm());
        return;
    }
    SG_ASSERT_OK(st);
    const std::string name = UniqueName("tpm");
    IdentityInfo id;
    const Status created = EnsureIdentity(*store, name, &id);
    if (created == SG_NOT_SUPPORTED) {
        // Reported, not hidden: the provider exists but there is no TPM 2.0.
        std::fprintf(stderr, "    no TPM 2.0 on this machine: TPM key creation not exercised\n");
        SG_EXPECT(!RequireTpm());
        crypto::P256PublicKey pub;
        SG_EXPECT_STATUS(store->GetPublicKey(name, &pub), SG_NOT_FOUND);
        return;
    }
    SG_ASSERT_OK(created);
    SG_EXPECT(id.kind == KeyStoreKind::kCngTpm);
    SG_EXPECT(id.hardware_backed);
    ExpectWorkingKey(*store, name);
    SG_ASSERT_OK(store->DeleteKey(name));
    std::fprintf(stderr, "    TPM 2.0 key created, used and deleted\n");
}
#endif

#ifdef SOCKGATE_WITH_TPM2
SG_TEST(Tpm2KeyStore, KeysLiveInTheTpm)
{
    TempDir dir;
    std::unique_ptr<IKeyStore> store;
    SG_ASSERT_OK(CreateTpm2KeyStore(dir.str(), &store));
    SG_EXPECT(store->Kind() == KeyStoreKind::kTpm2);
    const std::string name = UniqueName("tpm2");
    IdentityInfo id;
    const Status created = EnsureIdentity(*store, name, &id);
    if (created == SG_NOT_SUPPORTED) {
        // Reported, not hidden: no /dev/tpmrm0 access and no SOCKGATE_TPM2_TCTI.
        std::fprintf(stderr, "    no reachable TPM 2.0: TPM2 key creation not exercised\n");
        SG_EXPECT(!RequireTpm());
        crypto::P256PublicKey pub;
        SG_EXPECT_STATUS(store->GetPublicKey(name, &pub), SG_NOT_FOUND);
        return;
    }
    SG_ASSERT_OK(created);
    SG_EXPECT(id.hardware_backed);
    ExpectWorkingKey(*store, name);
    SG_EXPECT_STATUS(store->GenerateKeyPair(name), SG_ALREADY_EXISTS);

    // The file holds only TPM-wrapped material; a new store instance uses it.
    std::unique_ptr<IKeyStore> again;
    SG_ASSERT_OK(CreateTpm2KeyStore(dir.str(), &again));
    IdentityInfo id2;
    SG_ASSERT_OK(GetIdentity(*again, name, &id2));
    SG_EXPECT(id2.installation_id == id.installation_id);
    ExpectWorkingKey(*again, name);
    SG_ASSERT_OK(store->DeleteKey(name));
    std::fprintf(stderr, "    TPM2 key created, used and deleted\n");
}

SG_TEST(Tpm2KeyStore, MalformedBlobsAreRefused)
{
    TempDir dir;
    std::unique_ptr<IKeyStore> store;
    SG_ASSERT_OK(CreateTpm2KeyStore(dir.str(), &store));
    const std::string name = UniqueName("bad");
    const fs::path file = dir.path() / (name + ".tpm2key");
    for (const Bytes& content : {Bytes{}, Bytes{'S', 'G', 'T', '2'}, Bytes(300, 0x41)}) {
        std::error_code ec;
        fs::remove(file, ec);
        WriteFileBytes(file, content);
        fs::permissions(file, fs::perms::owner_read | fs::perms::owner_write);
        crypto::P256PublicKey pub;
        SG_EXPECT_STATUS(store->GetPublicKey(name, &pub), SG_KEYSTORE_ERROR);
        crypto::P256Signature sig;
        SG_EXPECT_STATUS(store->Sign(name, Bytes{1}, &sig), SG_KEYSTORE_ERROR);
    }
}
#endif
