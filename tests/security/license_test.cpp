// Phase 7: license store and built-in authorization. The client's product,
// license and feature values are claims; these tests make sure only the
// server's license records turn them into permissions.
#include "sg_test.h"

#include "auth/builtin_authorizer.h"
#include "storage/client_registry.h"
#include "storage/license_store.h"

#include "sockgate_common/core/clock.h"
#include "sockgate_common/protocol/transcript.h"

#include <filesystem>
#include <fstream>
#include <iterator>

using namespace sg;
using namespace sg::server;

namespace {

constexpr uint64_t kNow = 1'700'000'000'000ull;

proto::InstallationId Iid(uint8_t fill)
{
    proto::InstallationId id{};
    id.fill(fill);
    return id;
}

LicenseRecord License(const std::string& id, uint64_t features, uint32_t seats = 0, uint64_t expires = 0)
{
    LicenseRecord rec;
    rec.license_id = id;
    rec.product_id = "prod";
    rec.features = features;
    rec.max_installations = seats;
    rec.expires_at_ms = expires;
    return rec;
}

struct Fixture {
    std::unique_ptr<ILicenseStore> store = CreateMemoryLicenseStore();
    std::unique_ptr<IClientRegistry> registry = CreateMemoryClientRegistry();
    bool require_license = false;
    bool allow_activation = true;
    AuthorizeHook hook;
    proto::InstallationId current{};  // installation the next Run() authorises

    Fixture() { current = AddInstallation(); }

    proto::InstallationId AddInstallation(const std::string& product = "", const std::string& license = "")
    {
        std::unique_ptr<crypto::SoftwareP256Key> key;
        SG_ASSERT_OK(crypto::SoftwareP256Key::Generate(&key));
        ClientRecord rec;
        SG_ASSERT_OK(key->PublicKey(&rec.public_key));
        SG_ASSERT_OK(proto::DeriveInstallationId(rec.public_key, &rec.installation_id));
        rec.product_id = product;
        rec.license_id = license;
        SG_ASSERT_OK(registry->Register(rec));
        return rec.installation_id;
    }

    ClientRecord Record()
    {
        ClientRecord rec;
        SG_ASSERT_OK(registry->Find(current, &rec));
        return rec;
    }

    AuthorizationDecision Run(const std::string& product, const std::string& license, bool has_features = false,
                              uint64_t features = 0)
    {
        const ClientRecord record = Record();
        AuthorizationRequest r;
        r.installation_id = current;
        r.record = &record;
        r.product_id = product;
        r.license_id = license;
        r.has_requested_features = has_features;
        r.requested_features = features;

        BuiltinAuthorizerConfig cfg;
        cfg.licenses = store.get();
        cfg.registry = registry.get();
        cfg.require_license = require_license;
        cfg.allow_activation = allow_activation;
        cfg.unix_ms = []() { return kNow; };
        cfg.hook = hook;
        BuiltinAuthorizer authorizer(std::move(cfg));
        AuthorizationDecision d;
        d.allow = true;  // must be overwritten
        d.granted_features = ~0ull;
        SG_ASSERT_OK(authorizer.Authorize(r, &d));
        return d;
    }

    uint32_t Seats(const std::string& id)
    {
        LicenseRecord rec;
        SG_ASSERT_OK(store->Find(id, &rec));
        return rec.seats_used;
    }
};

}  // namespace

SG_TEST(LicenseStore, SeatsRevocationAndValidation)
{
    auto store = CreateMemoryLicenseStore();
    SG_ASSERT_OK(store->Upsert(License("L1", 0x3, 2)));
    bool newly = false;
    SG_ASSERT_OK(store->BindSeat("L1", Iid(1), &newly));
    SG_EXPECT(newly);
    SG_ASSERT_OK(store->BindSeat("L1", Iid(1), &newly));  // idempotent
    SG_EXPECT(!newly);
    SG_ASSERT_OK(store->BindSeat("L1", Iid(2), &newly));
    SG_EXPECT_STATUS(store->BindSeat("L1", Iid(3), &newly), SG_LIMIT_EXCEEDED);
    SG_EXPECT(!newly);
    SG_EXPECT_OK(store->HasSeat("L1", Iid(2)));
    SG_EXPECT_STATUS(store->HasSeat("L1", Iid(3)), SG_NOT_FOUND);

    // Updating terms keeps the seats; shrinking the limit keeps existing seats
    // but admits no new ones.
    SG_ASSERT_OK(store->Upsert(License("L1", 0x1, 1)));
    LicenseRecord rec;
    SG_ASSERT_OK(store->Find("L1", &rec));
    SG_EXPECT_EQ(rec.seats_used, uint32_t{2});
    SG_EXPECT_EQ(rec.features, uint64_t{1});
    SG_EXPECT_STATUS(store->BindSeat("L1", Iid(3), &newly), SG_LIMIT_EXCEEDED);
    SG_ASSERT_OK(store->ReleaseSeat("L1", Iid(2)));
    SG_EXPECT_STATUS(store->ReleaseSeat("L1", Iid(2)), SG_NOT_FOUND);
    SG_ASSERT_OK(store->ReleaseSeat("L1", Iid(1)));
    SG_ASSERT_OK(store->BindSeat("L1", Iid(3), &newly));

    // Revocation is permanent.
    SG_ASSERT_OK(store->Revoke("L1"));
    SG_ASSERT_OK(store->Revoke("L1"));
    SG_EXPECT_STATUS(store->BindSeat("L1", Iid(4), &newly), SG_INVALID_STATE);
    SG_EXPECT_STATUS(store->Upsert(License("L1", 0x3)), SG_INVALID_STATE);
    SG_EXPECT_STATUS(store->Revoke("nope"), SG_NOT_FOUND);
    SG_EXPECT_STATUS(store->BindSeat("nope", Iid(1), &newly), SG_NOT_FOUND);

    // Identifiers are validated like protocol strings.
    SG_EXPECT_STATUS(store->Upsert(License("", 1)), SG_INVALID_ARGUMENT);
    SG_EXPECT_STATUS(store->Upsert(License(std::string(129, 'a'), 1)), SG_INVALID_ARGUMENT);
    SG_EXPECT_STATUS(store->Upsert(License("bad\nid", 1)), SG_INVALID_ARGUMENT);
    LicenseRecord no_product = License("L2", 1);
    no_product.product_id.clear();
    SG_EXPECT_STATUS(store->Upsert(no_product), SG_INVALID_ARGUMENT);
    SG_EXPECT_EQ(store->Count(), size_t{1});

    // Log references never contain the id itself.
    const std::string ref = LicenseLogRef("SECRET-LICENSE-KEY");
    SG_EXPECT_EQ(ref.size(), size_t{4 + 16});
    SG_EXPECT(ref.find("SECRET") == std::string::npos);
}

SG_TEST(LicenseStore, FilePersistenceAndCorruption)
{
    namespace fs = std::filesystem;
    const fs::path dir = fs::temp_directory_path() / ("sockgate-license-" + std::to_string(MonotonicMs()));
    fs::create_directories(dir);
    const std::string path = (dir / "licenses.bin").string();
    {
        std::unique_ptr<ILicenseStore> store;
        SG_ASSERT_OK(CreateFileLicenseStore(path, &store));
        SG_EXPECT_EQ(store->Count(), size_t{0});
        SG_ASSERT_OK(store->Upsert(License("L1", 0xF0, 3, kNow + 1000)));
        SG_ASSERT_OK(store->Upsert(License("L2", 0x1)));
        bool newly = false;
        SG_ASSERT_OK(store->BindSeat("L1", Iid(7), &newly));
        SG_ASSERT_OK(store->Revoke("L2"));
    }
    {
        std::unique_ptr<ILicenseStore> store;
        SG_ASSERT_OK(CreateFileLicenseStore(path, &store));
        SG_EXPECT_EQ(store->Count(), size_t{2});
        LicenseRecord rec;
        SG_ASSERT_OK(store->Find("L1", &rec));
        SG_EXPECT_EQ(rec.product_id, std::string("prod"));
        SG_EXPECT_EQ(rec.features, uint64_t{0xF0});
        SG_EXPECT_EQ(rec.expires_at_ms, kNow + 1000);
        SG_EXPECT_EQ(rec.max_installations, uint32_t{3});
        SG_EXPECT_EQ(rec.seats_used, uint32_t{1});
        SG_EXPECT_OK(store->HasSeat("L1", Iid(7)));
        SG_ASSERT_OK(store->Find("L2", &rec));
        SG_EXPECT(rec.status == LicenseStatus::kRevoked);
    }
    Bytes data;
    {
        std::ifstream f(path, std::ios::binary);
        data.assign(std::istreambuf_iterator<char>(f), std::istreambuf_iterator<char>());
    }
    auto write = [&](const Bytes& bytes) {
        std::ofstream f(path, std::ios::binary | std::ios::trunc);
        f.write(reinterpret_cast<const char*>(bytes.data()), static_cast<std::streamsize>(bytes.size()));
    };
    auto expect_rejected = [&](const Bytes& bytes) {
        write(bytes);
        std::unique_ptr<ILicenseStore> store;
        SG_EXPECT_STATUS(CreateFileLicenseStore(path, &store), SG_STORAGE_ERROR);
    };
    {
        Bytes truncated(data.begin(), data.end() - 1);
        expect_rejected(truncated);
        Bytes trailing = data;
        trailing.push_back(0);
        expect_rejected(trailing);
        Bytes magic = data;
        magic[0] ^= 1;
        expect_rejected(magic);
        // First record: header(10) | vec16 "L1" (4) | vec16 "prod" (6) | features(8) |
        // expires(8) | max_installations(4) | status(1): an unknown status must not load.
        Bytes status = data;
        status[10 + 4 + 6 + 8 + 8 + 4] = 0x7F;
        expect_rejected(status);
        // A control character inside the license id.
        Bytes id = data;
        id[10 + 2] = '\n';
        expect_rejected(id);
        // The same installation twice in one license's seat list.
        Bytes dup = data;
        const size_t seat_count = 10 + 4 + 6 + 8 + 8 + 4 + 1;
        dup[seat_count + 3] = 2;
        const Bytes seat(dup.begin() + static_cast<std::ptrdiff_t>(seat_count + 4),
                         dup.begin() + static_cast<std::ptrdiff_t>(seat_count + 4 + 16));
        dup.insert(dup.begin() + static_cast<std::ptrdiff_t>(seat_count + 4), seat.begin(), seat.end());
        expect_rejected(dup);
    }
    fs::remove_all(dir);
}

SG_TEST(Authorization, GrantsOnlyLicensedFeatures)
{
    Fixture f;
    SG_ASSERT_OK(f.store->Upsert(License("L1", 0b0110, 0, kNow + 60'000)));
    f.current = f.AddInstallation("prod", "L1");

    // Requested features are intersected with the license.
    AuthorizationDecision d = f.Run("prod", "", true, 0b1111'0011);
    SG_EXPECT(d.allow);
    SG_EXPECT_EQ(d.granted_features, uint64_t{0b0010});
    SG_EXPECT_EQ(d.license_expires_at_ms, kNow + 60'000);
    SG_EXPECT_EQ(d.license_id, std::string("L1"));
    SG_EXPECT(d.license_verified);

    // No request: everything the license entitles.
    d = f.Run("prod", "L1");
    SG_EXPECT_EQ(d.granted_features, uint64_t{0b0110});
    SG_EXPECT_EQ(f.Seats("L1"), uint32_t{1});

    // Unlicensed or unknown licenses grant nothing, whatever is requested.
    f.current = f.AddInstallation();
    d = f.Run("prod", "", true, ~0ull);
    SG_EXPECT(d.allow);
    SG_EXPECT_EQ(d.granted_features, uint64_t{0});
    SG_EXPECT_EQ(d.license_expires_at_ms, uint64_t{0});
    d = f.Run("prod", "FORGED", true, ~0ull);
    SG_EXPECT(d.allow);
    SG_EXPECT_EQ(d.granted_features, uint64_t{0});
    SG_EXPECT(!d.license_verified);
    SG_EXPECT(d.license_id.empty());  // an unverified claim is never recorded as the session's license
    SG_EXPECT(f.Record().license_id.empty());  // nothing was activated
}

SG_TEST(Authorization, InvalidLicensesAreDenied)
{
    Fixture f;
    SG_ASSERT_OK(f.store->Upsert(License("EXPIRED", 1, 0, kNow)));
    SG_ASSERT_OK(f.store->Upsert(License("REVOKED", 1)));
    SG_ASSERT_OK(f.store->Revoke("REVOKED"));
    LicenseRecord other = License("OTHER", 1);
    other.product_id = "other-product";
    SG_ASSERT_OK(f.store->Upsert(other));

    for (const char* id : {"EXPIRED", "REVOKED", "OTHER"}) {
        const AuthorizationDecision d = f.Run("prod", id, true, 1);
        SG_EXPECT(!d.allow);
        SG_EXPECT_EQ(d.granted_features, uint64_t{0});
        SG_EXPECT(!d.deny_reason.empty());
    }
    // A license needs a product: an absent product claim cannot match.
    SG_ASSERT_OK(f.store->Upsert(License("L1", 1)));
    SG_EXPECT(!f.Run("", "L1").allow);
    SG_EXPECT(f.Record().license_id.empty());
    // Inactive installations are denied before any license logic.
    SG_ASSERT_OK(f.registry->Revoke(f.current));
    SG_EXPECT(!f.Run("prod", "L1").allow);
    SG_EXPECT_EQ(f.Seats("L1"), uint32_t{0});
}

SG_TEST(Authorization, RegistryBindingsWinOverClaims)
{
    Fixture f;
    SG_ASSERT_OK(f.store->Upsert(License("BOUND", 0x1)));
    SG_ASSERT_OK(f.store->Upsert(License("RICH", 0xFF)));
    f.current = f.AddInstallation("prod", "BOUND");

    // Claiming another (better) license than the registered one is refused.
    SG_EXPECT(!f.Run("prod", "RICH", true, 0xFF).allow);
    // So is claiming another product.
    SG_EXPECT(!f.Run("other-product", "").allow);
    // No claim: the registered binding applies.
    AuthorizationDecision d = f.Run("", "", true, 0xFF);
    SG_EXPECT(d.allow);
    SG_EXPECT_EQ(d.license_id, std::string("BOUND"));
    SG_EXPECT_EQ(d.granted_features, uint64_t{0x1});
    SG_EXPECT_EQ(f.Seats("RICH"), uint32_t{0});

    // A registered license the store does not know is kept but grants nothing.
    f.current = f.AddInstallation("prod", "EXTERNAL");
    d = f.Run("prod", "");
    SG_EXPECT(d.allow);
    SG_EXPECT_EQ(d.license_id, std::string("EXTERNAL"));
    SG_EXPECT(!d.license_verified);
    SG_EXPECT_EQ(d.granted_features, uint64_t{0});
}

SG_TEST(Authorization, ClaimsNeedActivation)
{
    Fixture f;
    f.allow_activation = false;
    SG_ASSERT_OK(f.store->Upsert(License("L1", 0xF)));
    LicenseCheck seen = LicenseCheck::kValid;
    f.hook = [&](const AuthorizationRequest& r, AuthorizationDecision*) {
        seen = r.license_status;
        return OkStatus();
    };
    // Knowing a license id is not enough: without a binding it is an
    // unverified claim that grants nothing and takes no seat.
    AuthorizationDecision d = f.Run("prod", "L1", true, 0xF);
    SG_EXPECT(d.allow);
    SG_EXPECT(seen == LicenseCheck::kUnknown);
    SG_EXPECT_EQ(d.granted_features, uint64_t{0});
    SG_EXPECT(d.license_id.empty());
    SG_EXPECT_EQ(f.Seats("L1"), uint32_t{0});
    SG_EXPECT(f.Record().license_id.empty());
    // Existing and non-existing ids are indistinguishable.
    const AuthorizationDecision unknown = f.Run("prod", "NOPE", true, 0xF);
    SG_EXPECT_EQ(unknown.allow, d.allow);
    SG_EXPECT_EQ(unknown.granted_features, d.granted_features);
    SG_EXPECT_EQ(unknown.license_expires_at_ms, d.license_expires_at_ms);

    f.require_license = true;
    SG_EXPECT(!f.Run("prod", "L1").allow);
    SG_EXPECT(!f.Run("prod", "NOPE").allow);
}

SG_TEST(Authorization, ActivationPinsTheFirstLicense)
{
    Fixture f;
    SG_ASSERT_OK(f.store->Upsert(License("L1", 0x1)));
    SG_ASSERT_OK(f.store->Upsert(License("L2", 0x2)));

    AuthorizationDecision d = f.Run("prod", "L1");
    SG_EXPECT(d.allow);
    SG_EXPECT_EQ(d.granted_features, uint64_t{0x1});
    SG_EXPECT_EQ(f.Record().license_id, std::string("L1"));
    SG_EXPECT_EQ(f.Record().product_id, std::string("prod"));
    SG_EXPECT_EQ(f.Seats("L1"), uint32_t{1});

    // The installation cannot hop to another license (and take its seats).
    SG_EXPECT(!f.Run("prod", "L2").allow);
    SG_EXPECT_EQ(f.Seats("L2"), uint32_t{0});
    // Without a claim the pinned license applies.
    d = f.Run("prod", "");
    SG_EXPECT(d.allow);
    SG_EXPECT_EQ(d.license_id, std::string("L1"));

    // Losing a race against a concurrent activation of another license (it
    // lands while this authorization runs) gives this attempt's seat back.
    f.current = f.AddInstallation();
    f.hook = [&](const AuthorizationRequest& r, AuthorizationDecision*) {
        if (r.license_id == "L2") SG_EXPECT_OK(f.registry->BindLicense(f.current, "prod", "L1"));
        return OkStatus();
    };
    d = f.Run("prod", "L2");
    SG_EXPECT(!d.allow);
    SG_EXPECT_EQ(d.deny_reason, std::string("license activation failed"));
    SG_EXPECT_EQ(f.Seats("L2"), uint32_t{0});
    SG_EXPECT_EQ(f.Record().license_id, std::string("L1"));

    // An installation revoked while being authorised: the pin fails and the
    // seat this attempt took is given back.
    f.current = f.AddInstallation();
    f.hook = [&](const AuthorizationRequest&, AuthorizationDecision*) {
        SG_EXPECT_OK(f.registry->Revoke(f.current));
        return OkStatus();
    };
    const uint32_t before = f.Seats("L2");
    d = f.Run("prod", "L2");
    SG_EXPECT(!d.allow);
    SG_EXPECT_EQ(f.Seats("L2"), before);
    f.hook = nullptr;

    // A successful authorization reports whether it took the seat.
    f.current = f.AddInstallation();
    d = f.Run("prod", "L2");
    SG_EXPECT(d.allow && d.seat_newly_taken);
    d = f.Run("prod", "");
    SG_EXPECT(d.allow && !d.seat_newly_taken);

    // BindLicense: idempotent for the same license, first binding wins.
    SG_EXPECT_OK(f.registry->BindLicense(f.current, "prod", "L2"));
    SG_EXPECT_STATUS(f.registry->BindLicense(f.current, "prod", "L1"), SG_ALREADY_EXISTS);
    const proto::InstallationId other_product = f.AddInstallation("other-product");
    SG_EXPECT_STATUS(f.registry->BindLicense(other_product, "prod", "L1"), SG_INVALID_ARGUMENT);
}

SG_TEST(Authorization, SeatsAreTakenOnlyForAllowedSessions)
{
    Fixture f;
    SG_ASSERT_OK(f.store->Upsert(License("L1", 0x1, 1)));
    int calls = 0;
    bool deny = false;
    f.hook = [&](const AuthorizationRequest& r, AuthorizationDecision* d) {
        ++calls;
        SG_EXPECT(r.license_status == LicenseCheck::kValid);
        if (deny) d->allow = false;
        return OkStatus();
    };
    deny = true;
    SG_EXPECT(!f.Run("prod", "L1").allow);
    SG_EXPECT_EQ(f.Seats("L1"), uint32_t{0});
    SG_EXPECT(f.Record().license_id.empty());  // not activated either

    deny = false;
    SG_EXPECT(f.Run("prod", "L1").allow);
    SG_EXPECT(f.Run("prod", "L1").allow);  // same installation, same seat
    SG_EXPECT_EQ(f.Seats("L1"), uint32_t{1});

    // Seat limit: checked after the hook allowed; nothing is pinned.
    f.current = f.AddInstallation();
    const AuthorizationDecision d = f.Run("prod", "L1");
    SG_EXPECT(!d.allow);
    SG_EXPECT_EQ(d.deny_reason, std::string("license installation limit reached"));
    SG_EXPECT_EQ(d.granted_features, uint64_t{0});
    SG_EXPECT(f.Record().license_id.empty());
    SG_EXPECT_EQ(calls, 4);
}

SG_TEST(Authorization, RequireLicense)
{
    Fixture f;
    f.require_license = true;
    SG_ASSERT_OK(f.store->Upsert(License("L1", 0x1)));
    SG_EXPECT(!f.Run("prod", "").allow);
    SG_EXPECT(!f.Run("prod", "UNKNOWN").allow);
    SG_EXPECT(f.Run("prod", "L1").allow);
    f.current = f.AddInstallation("prod", "EXTERNAL");  // registered, but not in the store
    SG_EXPECT(!f.Run("prod", "").allow);
}

SG_TEST(Authorization, HookSeesVerifiedLicenseAndMayRefine)
{
    Fixture f;
    SG_ASSERT_OK(f.store->Upsert(License("L1", 0b111)));
    LicenseCheck seen = LicenseCheck::kNone;
    uint64_t seen_features = 0;
    f.hook = [&](const AuthorizationRequest& r, AuthorizationDecision* d) {
        seen = r.license_status;
        seen_features = r.license_features;
        SG_EXPECT(d->allow);
        d->granted_features &= 0b001;  // narrow
        return OkStatus();
    };
    AuthorizationDecision d = f.Run("prod", "L1");
    SG_EXPECT(d.allow);
    SG_EXPECT(seen == LicenseCheck::kValid);
    SG_EXPECT_EQ(seen_features, uint64_t{0b111});
    SG_EXPECT_EQ(d.granted_features, uint64_t{0b001});

    f.current = f.AddInstallation();
    d = f.Run("prod", "UNKNOWN");
    SG_EXPECT(seen == LicenseCheck::kUnknown);
    SG_EXPECT_EQ(seen_features, uint64_t{0});
    d = f.Run("prod", "");
    SG_EXPECT(seen == LicenseCheck::kNone);

    // A failing hook is a denial.
    f.hook = [](const AuthorizationRequest&, AuthorizationDecision*) { return Status(SG_INTERNAL_ERROR); };
    d = f.Run("prod", "L1");
    SG_EXPECT(!d.allow);
    SG_EXPECT_EQ(d.granted_features, uint64_t{0});
    SG_EXPECT_EQ(d.deny_reason, std::string("application callback failed"));
}
