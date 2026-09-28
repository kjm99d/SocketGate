// Fuzz target: the server's persisted registry and license files, loaded as
// untrusted input. Byte 0 selects the format. Whatever loads must survive a
// modification + persist + reload round trip. Files live in a private
// directory created for this process and removed at exit.
#include "fuzz_target.h"

#include "storage/client_registry.h"
#include "storage/license_store.h"

#include "sockgate_common/core/bytes.h"
#include "sockgate_common/crypto/crypto.h"
#include "sockgate_common/protocol/transcript.h"

#include <cstdlib>
#include <filesystem>
#include <fstream>
#include <iterator>
#include <string>

#ifdef _WIN32
#include <process.h>
#define SG_GETPID _getpid
#else
#include <unistd.h>
#define SG_GETPID getpid
#endif

using namespace sg;
using namespace sg::server;

namespace {

void Check(bool condition)
{
    if (!condition) std::abort();
}

namespace fs = std::filesystem;

// A fresh directory under the temp dir that nobody else created (a name
// that already exists is never reused), removed when the process exits.
class PrivateDir {
public:
    PrivateDir()
    {
        for (int attempt = 0; attempt < 16 && dir_.empty(); ++attempt) {
            uint8_t nonce[8] = {};
            Check(crypto::RandomBytes(nonce, sizeof(nonce)).ok());
            const fs::path candidate = fs::temp_directory_path() / ("sockgate-fuzz-storage-" +
                                                                    std::to_string(SG_GETPID()) + "-" +
                                                                    ToHex(ByteView(nonce, sizeof(nonce))));
            std::error_code ec;
            if (fs::create_directory(candidate, ec)) {
                fs::permissions(candidate, fs::perms::owner_all, fs::perm_options::replace, ec);
                dir_ = candidate;
            }
        }
        Check(!dir_.empty());
    }
    ~PrivateDir()
    {
        std::error_code ec;
        fs::remove_all(dir_, ec);
    }
    std::string File() const { return (dir_ / "store.bin").string(); }

private:
    fs::path dir_;
};

const std::string& FilePath()
{
    static const PrivateDir dir;
    static const std::string path = dir.File();
    return path;
}

void RemoveInput()
{
    std::error_code ec;
    fs::remove(FilePath(), ec);
}

// False if the input could not be written (e.g. a scanner holds the file):
// the iteration is skipped rather than run on the previous input, which
// would make a crash irreproducible from its saved input.
bool WriteInput(const uint8_t* data, size_t size)
{
    std::ofstream f(FilePath(), std::ios::binary | std::ios::trunc);
    f.write(reinterpret_cast<const char*>(data), static_cast<std::streamsize>(size));
    f.close();
    return static_cast<bool>(f);
}

void FuzzRegistry()
{
    std::unique_ptr<IClientRegistry> registry;
    if (!CreateFileClientRegistry(FilePath(), &registry).ok()) return;
    const size_t count = registry->Count();
    ClientRecord first;
    bool have = false;
    registry->ForEach([&](const ClientRecord& r) {
        if (!have && r.status == ClientStatus::kActive) {
            first = r;
            have = true;
        }
    });
    if (!have) return;
    const Status revoked = registry->Revoke(first.installation_id);
    if (revoked == SG_STORAGE_ERROR) return;  // the environment, not the parser
    Check(revoked.ok());
    registry.reset();  // releases the store lock
    std::unique_ptr<IClientRegistry> reloaded;
    Check(CreateFileClientRegistry(FilePath(), &reloaded).ok());
    Check(reloaded->Count() == count);
    ClientRecord again;
    Check(reloaded->Find(first.installation_id, &again).ok() && again.status == ClientStatus::kRevoked);
}

void FuzzLicenses()
{
    std::unique_ptr<ILicenseStore> store;
    if (!CreateFileLicenseStore(FilePath(), &store).ok()) return;
    const size_t count = store->Count();
    LicenseRecord rec;
    rec.license_id = "fuzz-added-license";
    rec.product_id = "fuzz";
    rec.features = 1;
    const Status added = store->Upsert(rec);
    if (!added.ok()) return;  // e.g. the id exists and is revoked, or storage failed
    store.reset();             // releases the store lock
    std::unique_ptr<ILicenseStore> reloaded;
    Check(CreateFileLicenseStore(FilePath(), &reloaded).ok());
    LicenseRecord found;
    Check(reloaded->Find(rec.license_id, &found).ok() && found.features == 1);
    Check(reloaded->Count() == count || reloaded->Count() == count + 1);
}

}  // namespace

extern "C" int LLVMFuzzerTestOneInput(const uint8_t* data, size_t size)
{
    if (size < 1 || !WriteInput(data + 1, size - 1)) return 0;
    if (data[0] % 2 == 0) {
        FuzzRegistry();
    } else {
        FuzzLicenses();
    }
    return 0;
}

std::vector<std::vector<uint8_t>> SockGateFuzzSeeds()
{
    std::vector<std::vector<uint8_t>> seeds;
    auto snapshot = [&](uint8_t selector) {
        std::ifstream f(FilePath(), std::ios::binary);
        std::vector<uint8_t> v = {selector};
        v.insert(v.end(), std::istreambuf_iterator<char>(f), std::istreambuf_iterator<char>());
        seeds.push_back(v);
    };
    // A registry with two installations.
    RemoveInput();
    {
        std::unique_ptr<IClientRegistry> registry;
        if (CreateFileClientRegistry(FilePath(), &registry).ok()) {
            for (int i = 0; i < 2; ++i) {
                std::unique_ptr<crypto::SoftwareP256Key> key;
                ClientRecord rec;
                if (!crypto::SoftwareP256Key::Generate(&key).ok() || !key->PublicKey(&rec.public_key).ok() ||
                    !proto::DeriveInstallationId(rec.public_key, &rec.installation_id).ok()) {
                    continue;
                }
                rec.product_id = "prod";
                rec.license_id = i == 0 ? "L1" : "";
                (void)registry->Register(rec);
            }
        }
    }
    snapshot(0);
    // A license store with seats and a revoked license.
    RemoveInput();
    {
        std::unique_ptr<ILicenseStore> store;
        if (CreateFileLicenseStore(FilePath(), &store).ok()) {
            LicenseRecord a;
            a.license_id = "L1";
            a.product_id = "prod";
            a.features = 0xF;
            a.max_installations = 2;
            (void)store->Upsert(a);
            proto::InstallationId iid{};
            iid.fill(9);
            bool newly = false;
            (void)store->BindSeat("L1", iid, &newly);
            LicenseRecord b = a;
            b.license_id = "L2";
            (void)store->Upsert(b);
            (void)store->Revoke("L2");
        }
    }
    snapshot(1);
    RemoveInput();
    return seeds;
}
