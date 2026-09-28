// Phase 7: licenses end to end through the public C APIs. Every permission a
// client ends up with must come from the server's license records; claims
// that try to widen them are refused.
#include "sg_test.h"

#include "support/e2e_harness.h"

#include "sockgate_common/core/clock.h"

#include <atomic>
#include <chrono>
#include <cstring>
#include <filesystem>
#include <string>
#include <thread>

using namespace sgtest;

namespace {

constexpr const char* kProduct = "e2e-product";

SG_Status AddLicense(SG_Server* server, const char* id, uint64_t features, uint64_t expires_at_ms = 0,
                     uint32_t seats = 0, const char* product = kProduct)
{
    SG_LicenseRecord rec;
    SG_LicenseRecord_Init(&rec);
    rec.license_id = id;
    rec.product_id = product;
    rec.features = features;
    rec.expires_at_ms = expires_at_ms;
    rec.max_installations = seats;
    return SG_Server_AddLicense(server, &rec);
}

SG_LicenseInfo LicenseInfo(SG_Server* server, const char* id)
{
    SG_LicenseInfo info;
    SG_LicenseInfo_Init(&info);
    SG_ASSERT_OK(SG_Server_GetLicense(server, id, &info));
    return info;
}

ClientOptions Claims(const char* license, uint64_t requested = 0, const char* product = kProduct)
{
    ClientOptions o;
    o.license_id = license;
    o.requested_features = requested;
    o.product_id = product;
    return o;
}

SG_Status TryConnectAndAuth(SG_Client* c, uint16_t port)
{
    const SG_ServerConfig t = Target(port);
    const SG_Status st = SG_Client_Connect(c, &t);
    return st != SG_OK ? st : SG_Client_Authenticate(c);
}

SG_ClientSessionInfo ClientSession(SG_Client* c)
{
    SG_ClientSessionInfo si;
    SG_ClientSessionInfo_Init(&si);
    SG_ASSERT_OK(SG_Client_GetSessionInfo(c, &si));
    return si;
}

SG_InstallationId InstallationOf(SG_Client* c)
{
    SG_IdentityInfo id;
    SG_IdentityInfo_Init(&id);
    SG_ASSERT_OK(SG_Client_EnsureIdentity(c, &id));
    return id.installation_id;
}

void EnableActivation(SG_ServerOptions& o) { o.flags |= SG_SERVER_OPT_LICENSE_ACTIVATION; }

SG_ServerSessionInfo ServerSession(TestServer& server, size_t index)
{
    SG_ASSERT(server.WaitOpened(index + 1));
    SG_ServerSessionInfo ss;
    SG_ServerSessionInfo_Init(&ss);
    SG_ASSERT_OK(SG_Server_GetSessionInfo(server.server, server.opened[index], &ss));
    return ss;
}

// Receives until the session ends; returns the terminal status.
SG_Status WaitForSessionEnd(SG_Client* c, uint32_t timeout_ms = 5000)
{
    char buf[64];
    size_t n = 0;
    return SG_Client_ReceiveEx(c, buf, sizeof(buf), &n, nullptr, timeout_ms);
}

}  // namespace

SG_TEST(License, FeaturesComeFromTheLicense)
{
    TestServer server;
    server.configure = EnableActivation;
    server.Start();
    const uint64_t expiry = sg::UnixTimeMs() + 3'600'000;
    SG_ASSERT_OK(AddLicense(server.server, "LIC-A", 0b0110, expiry));

    // Asks for more than the license holds: only the intersection is granted.
    ClientPtr client(NewClient(Claims("LIC-A", 0b1111'0011)));
    server.Register(client.get());
    ConnectAndAuth(client.get(), server.port);
    SG_ClientSessionInfo si = ClientSession(client.get());
    SG_EXPECT_EQ(si.granted_features, uint64_t{0b0010});
    SG_EXPECT_EQ(si.license_expires_at_ms, expiry);

    const SG_ServerSessionInfo ss = ServerSession(server, 0);
    SG_EXPECT_EQ(ss.granted_features, uint64_t{0b0010});
    SG_EXPECT_EQ(std::string(ss.license_id), std::string("LIC-A"));
    SG_EXPECT_EQ(ss.license_status, uint32_t{SG_LICENSE_STATUS_VALID});
    SG_EXPECT_EQ(LicenseInfo(server.server, "LIC-A").installations, uint32_t{1});
    SG_ASSERT_OK(SG_Client_Disconnect(client.get()));

    // Requesting nothing means "whatever the license entitles".
    ClientPtr plain(NewClient(Claims("LIC-A"), "plain-app"));
    server.Register(plain.get());
    ConnectAndAuth(plain.get(), server.port);
    SG_EXPECT_EQ(ClientSession(plain.get()).granted_features, uint64_t{0b0110});

    // A license id the server does not know grants nothing and is not
    // reported as the session's license.
    ClientPtr forged(NewClient(Claims("LIC-FORGED", ~0ull), "forged-app"));
    server.Register(forged.get());
    ConnectAndAuth(forged.get(), server.port);
    si = ClientSession(forged.get());
    SG_EXPECT_EQ(si.granted_features, uint64_t{0});
    SG_EXPECT_EQ(si.license_expires_at_ms, uint64_t{0});
    const SG_ServerSessionInfo fs = ServerSession(server, 2);
    SG_EXPECT_EQ(std::string(fs.license_id), std::string());
    SG_EXPECT_EQ(fs.license_status, uint32_t{SG_LICENSE_STATUS_NONE});
}

SG_TEST(License, ClaimsWithoutActivationGrantNothing)
{
    TestServer server;
    server.Start();
    SG_ASSERT_OK(AddLicense(server.server, "LIC-KNOWN", 0xFF));
    for (const char* claim : {"LIC-KNOWN", "LIC-GUESS"}) {
        ClientPtr c(NewClient(Claims(claim, 0xFF), claim));
        server.Register(c.get());
        ConnectAndAuth(c.get(), server.port);
        const SG_ClientSessionInfo si = ClientSession(c.get());
        // Known and unknown ids look exactly the same to the client.
        SG_EXPECT_EQ(si.granted_features, uint64_t{0});
        SG_EXPECT_EQ(si.license_expires_at_ms, uint64_t{0});
    }
    SG_EXPECT_EQ(LicenseInfo(server.server, "LIC-KNOWN").installations, uint32_t{0});
}

SG_TEST(License, EscalationAttemptsAreRejected)
{
    TestServer server;
    server.configure = EnableActivation;
    server.Start();
    SG_ASSERT_OK(AddLicense(server.server, "BASIC", 0x1));
    SG_ASSERT_OK(AddLicense(server.server, "PREMIUM", 0xFF));
    SG_ASSERT_OK(AddLicense(server.server, "OTHER", 0xFF, 0, 0, "other-product"));
    SG_ASSERT_OK(AddLicense(server.server, "EXPIRED", 0xFF, sg::UnixTimeMs() - 1));

    // Installation registered under BASIC claims PREMIUM, then another product.
    {
        ClientPtr c(NewClient(Claims("PREMIUM", 0xFF)));
        SG_ASSERT_OK(server.TryRegister(c.get(), kProduct, "BASIC"));
        SG_EXPECT_STATUS(TryConnectAndAuth(c.get(), server.port), SG_SERVER_REJECTED);
    }
    {
        ClientPtr c(NewClient(Claims(nullptr, 0, "other-product"), "app-2"));
        SG_ASSERT_OK(server.TryRegister(c.get(), kProduct, "BASIC"));
        SG_EXPECT_STATUS(TryConnectAndAuth(c.get(), server.port), SG_SERVER_REJECTED);
    }
    // Unbound installation claims a license of another product, or an expired one.
    {
        ClientPtr c(NewClient(Claims("OTHER", 0xFF), "app-3"));
        server.Register(c.get());
        SG_EXPECT_STATUS(TryConnectAndAuth(c.get(), server.port), SG_SERVER_REJECTED);
    }
    {
        ClientPtr c(NewClient(Claims("EXPIRED", 0xFF), "app-4"));
        server.Register(c.get());
        SG_EXPECT_STATUS(TryConnectAndAuth(c.get(), server.port), SG_SERVER_REJECTED);
    }
    // The bound installation without claims gets exactly its license.
    {
        ClientPtr c(NewClient(Claims(nullptr, 0xFF), "app-5"));
        SG_ASSERT_OK(server.TryRegister(c.get(), kProduct, "BASIC"));
        ConnectAndAuth(c.get(), server.port);
        SG_EXPECT_EQ(ClientSession(c.get()).granted_features, uint64_t{0x1});
    }
    SG_EXPECT_EQ(LicenseInfo(server.server, "PREMIUM").installations, uint32_t{0});

    SG_ServerStats stats;
    SG_ServerStats_Init(&stats);
    SG_ASSERT_OK(SG_Server_GetStats(server.server, &stats));
    SG_EXPECT_EQ(stats.auth_failed, uint64_t{4});
}

SG_TEST(License, ExpiryCapsSessionLifetime)
{
    TestServer server;
    server.Start();
    SG_ASSERT_OK(AddLicense(server.server, "SHORT", 0x1, sg::UnixTimeMs() + 1500));
    ClientPtr client(NewClient());
    SG_ASSERT_OK(server.TryRegister(client.get(), kProduct, "SHORT"));
    ConnectAndAuth(client.get(), server.port);
    SG_EXPECT(ClientSession(client.get()).expires_in_ms <= 1500);
    SG_EXPECT_STATUS(WaitForSessionEnd(client.get(), 8000), SG_SESSION_EXPIRED);
    // Once expired the license admits nobody.
    SG_EXPECT_STATUS(TryConnectAndAuth(client.get(), server.port), SG_SERVER_REJECTED);
}

SG_TEST(License, RevocationClosesSessionsImmediately)
{
    TestServer server;
    server.Start();
    SG_ASSERT_OK(AddLicense(server.server, "LIC-R", 0x3));
    SG_ASSERT_OK(AddLicense(server.server, "LIC-KEEP", 0x3));
    ClientPtr a(NewClient(ClientOptions(), "app-a"));
    ClientPtr b(NewClient(ClientOptions(), "app-b"));
    ClientPtr keep(NewClient(ClientOptions(), "app-keep"));
    SG_ASSERT_OK(server.TryRegister(a.get(), kProduct, "LIC-R"));
    SG_ASSERT_OK(server.TryRegister(b.get(), kProduct, "LIC-R"));
    SG_ASSERT_OK(server.TryRegister(keep.get(), kProduct, "LIC-KEEP"));
    for (SG_Client* c : {a.get(), b.get(), keep.get()}) ConnectAndAuth(c, server.port);

    SG_ASSERT_OK(SG_Server_RevokeLicense(server.server, "LIC-R"));
    SG_EXPECT_STATUS(WaitForSessionEnd(a.get()), SG_SERVER_REJECTED);
    SG_EXPECT_STATUS(WaitForSessionEnd(b.get()), SG_SERVER_REJECTED);
    SG_EXPECT_STATUS(TryConnectAndAuth(a.get(), server.port), SG_SERVER_REJECTED);

    // Sessions under other licenses are untouched.
    SG_ASSERT_OK(SG_Client_Send(keep.get(), "still", 5));
    SG_EXPECT_EQ(ReceiveText(keep.get()), std::string("still"));

    // Revocation is permanent and visible.
    SG_EXPECT_EQ(LicenseInfo(server.server, "LIC-R").revoked, uint32_t{1});
    SG_EXPECT_STATUS(AddLicense(server.server, "LIC-R", 0xFF), SG_INVALID_STATE);
    SG_EXPECT_STATUS(SG_Server_RevokeLicense(server.server, "LIC-NONE"), SG_NOT_FOUND);
}

SG_TEST(License, RevocationDuringAuthorizationIsNotMissed)
{
    TestServer server;
    std::atomic<int> mode{0};  // 1 = revoke the license, 2 = revoke the installation
    server.authorize = [&](const SG_AuthRequest* r, SG_AuthDecision*) {
        // The session is not open yet, so the revocation pass cannot see it.
        if (mode.load() == 1) SG_EXPECT_OK(SG_Server_RevokeLicense(server.server, "LIC-RACE"));
        if (mode.load() == 2) SG_EXPECT_OK(SG_Server_RevokeClient(server.server, &r->installation_id));
        return SG_OK;
    };
    server.Start();
    SG_ASSERT_OK(AddLicense(server.server, "LIC-RACE", 0x1));
    SG_ASSERT_OK(AddLicense(server.server, "LIC-OK", 0x1, 0, 5));

    ClientPtr a(NewClient(ClientOptions(), "race-a"));
    SG_ASSERT_OK(server.TryRegister(a.get(), kProduct, "LIC-RACE"));
    mode = 1;
    SG_EXPECT_STATUS(TryConnectAndAuth(a.get(), server.port), SG_SERVER_REJECTED);

    ClientPtr b(NewClient(ClientOptions(), "race-b"));
    SG_ASSERT_OK(server.TryRegister(b.get(), kProduct, "LIC-OK"));
    mode = 2;
    SG_EXPECT_STATUS(TryConnectAndAuth(b.get(), server.port), SG_SERVER_REJECTED);
    // The seat taken for the revoked installation was given back.
    SG_EXPECT_EQ(LicenseInfo(server.server, "LIC-OK").installations, uint32_t{0});

    // Unrelated revocations do not reject a concurrently authorised session.
    ClientPtr c(NewClient(ClientOptions(), "race-c"));
    ClientPtr victim(NewClient(ClientOptions(), "race-victim"));
    SG_ASSERT_OK(server.TryRegister(c.get(), kProduct, "LIC-OK"));
    server.Register(victim.get());
    const SG_InstallationId victim_id = InstallationOf(victim.get());
    mode = 0;
    server.authorize = [&](const SG_AuthRequest*, SG_AuthDecision*) {
        SG_EXPECT_OK(SG_Server_RevokeClient(server.server, &victim_id));
        return SG_OK;
    };
    ConnectAndAuth(c.get(), server.port);
    SG_EXPECT_EQ(StateOf(c.get()), SG_CLIENT_STATE_ACTIVE);
}

SG_TEST(License, SeatLimitAndRelease)
{
    TestServer server;
    server.Start();
    SG_ASSERT_OK(AddLicense(server.server, "ONE-SEAT", 0x1, 0, 1));
    ClientPtr a(NewClient(ClientOptions(), "seat-a"));
    ClientPtr b(NewClient(ClientOptions(), "seat-b"));
    SG_ASSERT_OK(server.TryRegister(a.get(), kProduct, "ONE-SEAT"));
    SG_ASSERT_OK(server.TryRegister(b.get(), kProduct, "ONE-SEAT"));

    ConnectAndAuth(a.get(), server.port);
    SG_EXPECT_STATUS(TryConnectAndAuth(b.get(), server.port), SG_SERVER_REJECTED);
    SG_EXPECT_EQ(LicenseInfo(server.server, "ONE-SEAT").installations, uint32_t{1});

    // Releasing A's seat ends A's session and lets B in; A is then out.
    const SG_InstallationId a_id = InstallationOf(a.get());
    SG_ASSERT_OK(SG_Server_ReleaseLicenseSeat(server.server, "ONE-SEAT", &a_id));
    SG_EXPECT_STATUS(WaitForSessionEnd(a.get()), SG_SERVER_REJECTED);
    SG_EXPECT_STATUS(SG_Server_ReleaseLicenseSeat(server.server, "ONE-SEAT", &a_id), SG_NOT_FOUND);
    ConnectAndAuth(b.get(), server.port);
    SG_EXPECT_STATUS(TryConnectAndAuth(a.get(), server.port), SG_SERVER_REJECTED);

    // Raising the limit admits A again without disturbing B.
    SG_ASSERT_OK(AddLicense(server.server, "ONE-SEAT", 0x1, 0, 2));
    ConnectAndAuth(a.get(), server.port);
    SG_EXPECT_EQ(LicenseInfo(server.server, "ONE-SEAT").installations, uint32_t{2});
    SG_EXPECT_EQ(StateOf(b.get()), SG_CLIENT_STATE_ACTIVE);
}

SG_TEST(License, RevokingAnInstallationFreesItsSeat)
{
    TestServer server;
    server.configure = EnableActivation;
    server.Start();
    SG_ASSERT_OK(AddLicense(server.server, "SEAT", 0x1, 0, 1));
    ClientPtr a(NewClient(Claims("SEAT"), "free-a"));
    ClientPtr b(NewClient(Claims("SEAT"), "free-b"));
    server.Register(a.get());
    server.Register(b.get());
    ConnectAndAuth(a.get(), server.port);  // activates: seat + binding
    SG_EXPECT_STATUS(TryConnectAndAuth(b.get(), server.port), SG_SERVER_REJECTED);

    const SG_InstallationId a_id = InstallationOf(a.get());
    SG_ASSERT_OK(SG_Server_RevokeClient(server.server, &a_id));
    SG_EXPECT_STATUS(WaitForSessionEnd(a.get()), SG_SERVER_REJECTED);
    SG_EXPECT_EQ(LicenseInfo(server.server, "SEAT").installations, uint32_t{0});
    ConnectAndAuth(b.get(), server.port);
    SG_EXPECT_EQ(ClientSession(b.get()).granted_features, uint64_t{0x1});
}

SG_TEST(License, RequireLicenseOption)
{
    TestServer server;
    server.configure = [](SG_ServerOptions& o) { o.flags |= SG_SERVER_OPT_REQUIRE_LICENSE; };
    server.Start();
    SG_ASSERT_OK(AddLicense(server.server, "LIC-REQ", 0x4));

    ClientPtr none(NewClient(ClientOptions(), "req-none"));
    server.Register(none.get());
    SG_EXPECT_STATUS(TryConnectAndAuth(none.get(), server.port), SG_SERVER_REJECTED);

    ClientPtr unknown(NewClient(Claims("LIC-UNKNOWN"), "req-unknown"));
    server.Register(unknown.get());
    SG_EXPECT_STATUS(TryConnectAndAuth(unknown.get(), server.port), SG_SERVER_REJECTED);

    ClientPtr ok(NewClient(ClientOptions(), "req-ok"));
    SG_ASSERT_OK(server.TryRegister(ok.get(), kProduct, "LIC-REQ"));
    ConnectAndAuth(ok.get(), server.port);
    SG_EXPECT_EQ(ClientSession(ok.get()).granted_features, uint64_t{0x4});

    // Bindings to licenses the store does not know are refused up front.
    ClientPtr bound(NewClient(ClientOptions(), "req-bound"));
    SG_EXPECT_STATUS(server.TryRegister(bound.get(), kProduct, "LIC-UNKNOWN"), SG_NOT_FOUND);
    SG_EnrollmentTokenRequest req;
    SG_EnrollmentTokenRequest_Init(&req);
    req.product_id = kProduct;
    req.license_id = "LIC-UNKNOWN";
    char token[1024];
    size_t written = 0;
    SG_EXPECT_STATUS(SG_Server_IssueEnrollmentToken(server.server, &req, token, sizeof(token), &written),
                     SG_NOT_FOUND);
}

SG_TEST(License, BindingsAreCheckedAgainstTheStore)
{
    TestServer server;
    server.configure = [](SG_ServerOptions& o) { o.flags |= SG_SERVER_OPT_ALLOW_ENROLLMENT; };
    server.Start();
    SG_ASSERT_OK(AddLicense(server.server, "LIC-ENR", 0x30));
    SG_ASSERT_OK(AddLicense(server.server, "LIC-DEAD", 0x30));
    SG_ASSERT_OK(SG_Server_RevokeLicense(server.server, "LIC-DEAD"));

    SG_EnrollmentTokenRequest req;
    SG_EnrollmentTokenRequest_Init(&req);
    req.product_id = kProduct;
    char token[1024];
    size_t written = 0;
    req.license_id = "LIC-DEAD";
    SG_EXPECT_STATUS(SG_Server_IssueEnrollmentToken(server.server, &req, token, sizeof(token), &written),
                     SG_INVALID_STATE);
    req.product_id = "other-product";
    req.license_id = "LIC-ENR";
    SG_EXPECT_STATUS(SG_Server_IssueEnrollmentToken(server.server, &req, token, sizeof(token), &written),
                     SG_INVALID_ARGUMENT);
    ClientPtr reg(NewClient(ClientOptions(), "bind-reg"));
    SG_EXPECT_STATUS(server.TryRegister(reg.get(), kProduct, "LIC-DEAD"), SG_INVALID_STATE);
    SG_EXPECT_STATUS(server.TryRegister(reg.get(), "other-product", "LIC-ENR"), SG_INVALID_ARGUMENT);

    // A token bound to the license: the enrolled installation gets its features.
    req.product_id = kProduct;
    SG_ASSERT_OK(SG_Server_IssueEnrollmentToken(server.server, &req, token, sizeof(token), &written));
    ClientPtr client(NewClient(ClientOptions(), "bind-enroll"));
    const SG_ServerConfig t = Target(server.port);
    SG_ASSERT_OK(SG_Client_Connect(client.get(), &t));
    SG_ASSERT_OK(SG_Client_Enroll(client.get(), token));
    SG_EXPECT_EQ(ClientSession(client.get()).granted_features, uint64_t{0x30});
    SG_EXPECT_EQ(LicenseInfo(server.server, "LIC-ENR").installations, uint32_t{1});
}

SG_TEST(License, AuthorizeCallbackSeesLicenseCheck)
{
    TestServer server;
    std::atomic<uint32_t> status{99};
    std::atomic<uint64_t> features{0};
    server.authorize = [&](const SG_AuthRequest* r, SG_AuthDecision* d) {
        status = r->license_status;
        features = r->license_features;
        // The application is trusted and may narrow or widen the grant.
        if (r->license_status == SG_LICENSE_STATUS_UNKNOWN) d->granted_features = 0x100;
        return SG_OK;
    };
    server.Start();
    SG_ASSERT_OK(AddLicense(server.server, "LIC-CB", 0x7));

    ClientPtr valid(NewClient(ClientOptions(), "cb-valid"));
    SG_ASSERT_OK(server.TryRegister(valid.get(), kProduct, "LIC-CB"));
    ConnectAndAuth(valid.get(), server.port);
    SG_EXPECT_EQ(status.load(), uint32_t{SG_LICENSE_STATUS_VALID});
    SG_EXPECT_EQ(features.load(), uint64_t{0x7});

    ClientPtr unknown(NewClient(Claims("LIC-EXTERNAL"), "cb-unknown"));
    server.Register(unknown.get());
    ConnectAndAuth(unknown.get(), server.port);
    SG_EXPECT_EQ(status.load(), uint32_t{SG_LICENSE_STATUS_UNKNOWN});
    SG_EXPECT_EQ(features.load(), uint64_t{0});
    SG_EXPECT_EQ(ClientSession(unknown.get()).granted_features, uint64_t{0x100});

    ClientPtr none(NewClient(ClientOptions(), "cb-none"));
    server.Register(none.get());
    ConnectAndAuth(none.get(), server.port);
    SG_EXPECT_EQ(status.load(), uint32_t{SG_LICENSE_STATUS_NONE});

    // A registered license the store does not know: kept, reported UNKNOWN.
    ClientPtr external(NewClient(ClientOptions(), "cb-external"));
    SG_ASSERT_OK(server.TryRegister(external.get(), kProduct, "LIC-EXTERNAL"));
    ConnectAndAuth(external.get(), server.port);
    SG_EXPECT_EQ(status.load(), uint32_t{SG_LICENSE_STATUS_UNKNOWN});
    const SG_ServerSessionInfo ss = ServerSession(server, 3);
    SG_EXPECT_EQ(std::string(ss.license_id), std::string("LIC-EXTERNAL"));
    SG_EXPECT_EQ(ss.license_status, uint32_t{SG_LICENSE_STATUS_UNKNOWN});
}

SG_TEST(License, RefreshAppliesChangedTerms)
{
    TestServer server;
    server.configure = [](SG_ServerOptions& o) { o.min_reauth_interval_ms = 1; };
    server.Start();
    SG_ASSERT_OK(AddLicense(server.server, "LIC-TERMS", 0b0110));
    ClientPtr client(NewClient());
    SG_ASSERT_OK(server.TryRegister(client.get(), kProduct, "LIC-TERMS"));
    ConnectAndAuth(client.get(), server.port);
    SG_ASSERT(server.WaitOpened(1));
    const SG_SessionHandle session = server.opened[0];

    // Narrowed features apply at the next refresh.
    SG_ASSERT_OK(AddLicense(server.server, "LIC-TERMS", 0b0010));
    std::this_thread::sleep_for(std::chrono::milliseconds(20));
    SG_ASSERT_OK(SG_Client_Refresh(client.get()));
    SG_ServerSessionInfo ss;
    SG_ServerSessionInfo_Init(&ss);
    SG_ASSERT_OK(SG_Server_GetSessionInfo(server.server, session, &ss));
    SG_EXPECT_EQ(ss.granted_features, uint64_t{0b0010});

    // An expiry moved into the past ends the session at the next refresh.
    SG_ASSERT_OK(AddLicense(server.server, "LIC-TERMS", 0b0010, sg::UnixTimeMs() - 1));
    std::this_thread::sleep_for(std::chrono::milliseconds(20));
    SG_EXPECT(SG_Client_Refresh(client.get()) != SG_OK);
    SG_EXPECT_EQ(StateOf(client.get()), SG_CLIENT_STATE_CLOSED);
}

SG_TEST(License, PersistentLicenseStore)
{
    namespace fs = std::filesystem;
    const fs::path dir = fs::temp_directory_path() / ("sockgate-e2e-license-" + std::to_string(sg::MonotonicMs()));
    fs::create_directories(dir);
    const std::string license_path = (dir / "licenses.bin").string();
    const std::string registry_path = (dir / "registry.bin").string();
    auto paths = [&](SG_ServerOptions& o) {
        o.license_path = license_path.c_str();
        o.registry_path = registry_path.c_str();
    };

    ClientPtr client(NewClient(Claims("LIC-P")));
    {
        TestServer server;
        server.configure = [&](SG_ServerOptions& o) {
            paths(o);
            EnableActivation(o);  // the claim activates LIC-P and pins it
        };
        server.Start();
        SG_ASSERT_OK(AddLicense(server.server, "LIC-P", 0x9, 0, 1));
        server.Register(client.get());
        ConnectAndAuth(client.get(), server.port);
        SG_ASSERT_OK(SG_Client_Disconnect(client.get()));
    }
    {
        TestServer server;
        server.configure = paths;
        server.Start();
        const SG_LicenseInfo info = LicenseInfo(server.server, "LIC-P");
        SG_EXPECT_EQ(info.features, uint64_t{0x9});
        SG_EXPECT_EQ(info.installations, uint32_t{1});
        SG_EXPECT_EQ(std::string(info.product_id), std::string(kProduct));
        // Activation is off now: the license only applies because the first
        // server pinned it to the installation, and the pin was persisted.
        ConnectAndAuth(client.get(), server.port);
        SG_EXPECT_EQ(ClientSession(client.get()).granted_features, uint64_t{0x9});
        SG_ASSERT_OK(SG_Server_RevokeLicense(server.server, "LIC-P"));
        SG_EXPECT_STATUS(WaitForSessionEnd(client.get()), SG_SERVER_REJECTED);
    }
    {
        TestServer server;
        server.configure = paths;
        server.Start();
        SG_EXPECT_EQ(LicenseInfo(server.server, "LIC-P").revoked, uint32_t{1});
        SG_EXPECT_STATUS(TryConnectAndAuth(client.get(), server.port), SG_SERVER_REJECTED);
    }

    // The registry and the license store cannot share a file.
    SG_ServerOptions opts;
    SG_ServerOptions_Init(&opts);
    opts.tls_cert_chain_pem = Leaf().cert_pem.c_str();
    opts.tls_private_key_pem = Leaf().key_pem.c_str();
    opts.registry_path = license_path.c_str();
    opts.license_path = license_path.c_str();
    SG_Server* bad = nullptr;
    SG_EXPECT_STATUS(SG_Server_Create(&opts, &bad), SG_INVALID_ARGUMENT);
    SG_EXPECT(bad == nullptr);
    fs::remove_all(dir);
}

SG_TEST(License, ApiArgumentValidation)
{
    TestServer server;
    server.Start();
    SG_LicenseRecord rec;
    SG_LicenseRecord_Init(&rec);
    SG_EXPECT_STATUS(SG_Server_AddLicense(server.server, &rec), SG_INVALID_ARGUMENT);  // no ids
    rec.license_id = "LIC-V";
    SG_EXPECT_STATUS(SG_Server_AddLicense(server.server, &rec), SG_INVALID_ARGUMENT);  // no product
    rec.product_id = kProduct;
    SG_ASSERT_OK(SG_Server_AddLicense(server.server, &rec));
    const std::string long_id(129, 'x');
    rec.license_id = long_id.c_str();
    SG_EXPECT_STATUS(SG_Server_AddLicense(server.server, &rec), SG_INVALID_ARGUMENT);
    rec.license_id = "LIC\x1b[31m";
    SG_EXPECT_STATUS(SG_Server_AddLicense(server.server, &rec), SG_INVALID_ARGUMENT);
    SG_LicenseRecord old_struct = rec;
    old_struct.size = 8;
    SG_EXPECT_STATUS(SG_Server_AddLicense(server.server, &old_struct), SG_INVALID_ARGUMENT);

    SG_EXPECT_STATUS(SG_Server_AddLicense(nullptr, &rec), SG_INVALID_ARGUMENT);
    SG_EXPECT_STATUS(SG_Server_RevokeLicense(server.server, nullptr), SG_INVALID_ARGUMENT);
    SG_EXPECT_STATUS(SG_Server_RevokeLicense(server.server, ""), SG_INVALID_ARGUMENT);
    SG_InstallationId iid;
    std::memset(&iid, 0, sizeof(iid));
    SG_EXPECT_STATUS(SG_Server_ReleaseLicenseSeat(server.server, "LIC-V", nullptr), SG_INVALID_ARGUMENT);
    SG_EXPECT_STATUS(SG_Server_ReleaseLicenseSeat(server.server, "LIC-V", &iid), SG_NOT_FOUND);
    SG_LicenseInfo info;
    SG_LicenseInfo_Init(&info);
    SG_EXPECT_STATUS(SG_Server_GetLicense(server.server, "LIC-NONE", &info), SG_NOT_FOUND);
    info.size = 16;
    SG_EXPECT_STATUS(SG_Server_GetLicense(server.server, "LIC-V", &info), SG_INVALID_ARGUMENT);
}
