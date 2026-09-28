// Phase 9: integrity reports end to end. Reports only ever lower trust:
// missing or suspicious reports restrict or reject sessions per server policy.
#include "sg_test.h"

#include "support/e2e_harness.h"

#include "sockgate_common/crypto/crypto.h"

#include <atomic>
#include <cstring>
#include <fstream>
#include <iterator>
#include <mutex>
#include <string>

#ifdef _WIN32
#include <windows.h>
#endif

using namespace sgtest;

namespace {

SG_Sha256 OwnExecutableHash()
{
#ifdef _WIN32
    wchar_t path[MAX_PATH * 4];
    const DWORD n = GetModuleFileNameW(nullptr, path, static_cast<DWORD>(std::size(path)));
    SG_ASSERT(n > 0 && n < std::size(path));
    std::ifstream f(path, std::ios::binary);
#else
    std::ifstream f("/proc/self/exe", std::ios::binary);
#endif
    const sg::Bytes content((std::istreambuf_iterator<char>(f)), std::istreambuf_iterator<char>());
    sg::crypto::Sha256Digest digest;
    SG_ASSERT_OK(sg::crypto::Sha256(content, &digest));
    SG_Sha256 out;
    std::memcpy(out.bytes, digest.data(), sizeof(out.bytes));
    return out;
}

ClientOptions Reporting()
{
    ClientOptions o;
    o.flags = SG_CLIENT_FLAG_INTEGRITY_REPORT;
    return o;
}

uint32_t PolicyOf(SG_Client* c)
{
    SG_ClientSessionInfo si;
    SG_ClientSessionInfo_Init(&si);
    SG_ASSERT_OK(SG_Client_GetSessionInfo(c, &si));
    return si.policy;
}

SG_Status TryConnectAndAuth(SG_Client* c, uint16_t port)
{
    const SG_ServerConfig t = Target(port);
    const SG_Status st = SG_Client_Connect(c, &t);
    return st != SG_OK ? st : SG_Client_Authenticate(c);
}

}  // namespace

SG_TEST(Integrity, ReportReachesTheServer)
{
    TestServer server;
    std::mutex mutex;
    uint32_t present = 0;
    uint32_t platform = 0;
    uint32_t conditions = 0;
    SG_Sha256 exe{};
    server.authorize = [&](const SG_AuthRequest* r, SG_AuthDecision*) {
        std::lock_guard<std::mutex> lock(mutex);
        present = r->integrity_present;
        platform = r->integrity_platform;
        conditions = r->integrity_conditions;
        if (r->executable_sha256 != nullptr) std::memcpy(exe.bytes, r->executable_sha256, sizeof(exe.bytes));
        return SG_OK;
    };
    server.Start();

    ClientPtr client(NewClient(Reporting()));
    server.Register(client.get());
    ConnectAndAuth(client.get(), server.port);
    {
        std::lock_guard<std::mutex> lock(mutex);
        SG_EXPECT_EQ(present, 1u);
#ifdef _WIN32
        SG_EXPECT_EQ(platform, uint32_t{SG_INTEGRITY_PLATFORM_WINDOWS});
#else
        SG_EXPECT_EQ(platform, uint32_t{SG_INTEGRITY_PLATFORM_LINUX});
#endif
        const SG_Sha256 expected = OwnExecutableHash();
        SG_EXPECT(std::memcmp(exe.bytes, expected.bytes, sizeof(exe.bytes)) == 0);
        SG_EXPECT((conditions & (SG_INTEGRITY_REPORT_MISSING | SG_INTEGRITY_UNKNOWN_EXECUTABLE)) == 0);
    }
    SG_ASSERT_OK(SG_Client_Disconnect(client.get()));

    // Without the flag nothing is reported and the server notes it.
    ClientPtr silent(NewClient(ClientOptions(), "silent-app"));
    server.Register(silent.get());
    ConnectAndAuth(silent.get(), server.port);
    std::lock_guard<std::mutex> lock(mutex);
    SG_EXPECT_EQ(present, 0u);
    SG_EXPECT((conditions & SG_INTEGRITY_REPORT_MISSING) != 0);
}

SG_TEST(Integrity, MissingReportsRestrictOrReject)
{
    TestServer server;
    server.configure = [](SG_ServerOptions& o) { o.integrity_restrict_mask = SG_INTEGRITY_REPORT_MISSING; };
    server.Start();
    ClientPtr silent(NewClient(ClientOptions(), "silent-app"));
    ClientPtr reporting(NewClient(Reporting(), "reporting-app"));
    server.Register(silent.get());
    server.Register(reporting.get());
    ConnectAndAuth(silent.get(), server.port);
    SG_EXPECT_EQ(PolicyOf(silent.get()), uint32_t{SG_SESSION_POLICY_RESTRICTED});
    ConnectAndAuth(reporting.get(), server.port);
    SG_EXPECT_EQ(PolicyOf(reporting.get()), uint32_t{SG_SESSION_POLICY_NORMAL});
    SG_ASSERT_OK(SG_Client_Disconnect(silent.get()));
    SG_ASSERT_OK(SG_Client_Disconnect(reporting.get()));
    server.Destroy();

    TestServer strict;
    strict.configure = [](SG_ServerOptions& o) { o.integrity_reject_mask = SG_INTEGRITY_REPORT_MISSING; };
    strict.Start();
    strict.Register(silent.get());
    strict.Register(reporting.get());
    SG_EXPECT_STATUS(TryConnectAndAuth(silent.get(), strict.port), SG_SERVER_REJECTED);
    ConnectAndAuth(reporting.get(), strict.port);
}

SG_TEST(Integrity, ExecutableAllowlist)
{
    const SG_Sha256 own = OwnExecutableHash();
    SG_Sha256 other = own;
    other.bytes[0] ^= 0xFF;
    {
        TestServer server;
        server.configure = [&](SG_ServerOptions& o) {
            o.allowed_executables = &own;
            o.allowed_executable_count = 1;
            o.integrity_reject_mask = SG_INTEGRITY_UNKNOWN_EXECUTABLE;
        };
        server.Start();
        ClientPtr client(NewClient(Reporting()));
        server.Register(client.get());
        ConnectAndAuth(client.get(), server.port);
        // A client that does not report cannot pass an allowlist.
        ClientPtr silent(NewClient(ClientOptions(), "silent-app"));
        server.Register(silent.get());
        SG_EXPECT_STATUS(TryConnectAndAuth(silent.get(), server.port), SG_SERVER_REJECTED);
    }
    {
        TestServer server;
        server.configure = [&](SG_ServerOptions& o) {
            o.allowed_executables = &other;
            o.allowed_executable_count = 1;
            o.integrity_reject_mask = SG_INTEGRITY_UNKNOWN_EXECUTABLE;
        };
        server.Start();
        ClientPtr client(NewClient(Reporting()));
        server.Register(client.get());
        SG_EXPECT_STATUS(TryConnectAndAuth(client.get(), server.port), SG_SERVER_REJECTED);
    }
    // Invalid allowlist configuration.
    SG_ServerOptions opts;
    SG_ServerOptions_Init(&opts);
    opts.tls_cert_chain_pem = Leaf().cert_pem.c_str();
    opts.tls_private_key_pem = Leaf().key_pem.c_str();
    opts.allowed_executable_count = 1;  // but no array
    SG_Server* bad = nullptr;
    SG_EXPECT_STATUS(SG_Server_Create(&opts, &bad), SG_INVALID_ARGUMENT);
    opts.allowed_executables = &own;
    opts.allowed_executable_count = 4097;
    SG_EXPECT_STATUS(SG_Server_Create(&opts, &bad), SG_INVALID_ARGUMENT);
}

#ifdef _WIN32
SG_TEST(Integrity, UnsignedExecutableCanBeRestricted)
{
    // Test binaries are not Authenticode-signed.
    TestServer server;
    server.configure = [](SG_ServerOptions& o) { o.integrity_restrict_mask = SG_INTEGRITY_UNSIGNED_EXECUTABLE; };
    server.Start();
    ClientPtr client(NewClient(Reporting()));
    server.Register(client.get());
    ConnectAndAuth(client.get(), server.port);
    SG_EXPECT_EQ(PolicyOf(client.get()), uint32_t{SG_SESSION_POLICY_RESTRICTED});
}
#endif

SG_TEST(Integrity, UnknownClientFlagsAreRefused)
{
    SG_ClientConfig cfg;
    SG_ClientConfig_Init(&cfg);
    cfg.identity_name = "flags-app";
    cfg.key_store_type = SG_KEYSTORE_MEMORY;
    cfg.flags = 1u << 20;
    SG_Client* client = nullptr;
    SG_EXPECT_STATUS(SG_Client_Create(&cfg, &client), SG_NOT_SUPPORTED);
    SG_EXPECT(client == nullptr);
}

SG_TEST(Integrity, OptionsAreValidated)
{
    SG_ServerOptions opts;
    SG_ServerOptions_Init(&opts);
    opts.tls_cert_chain_pem = Leaf().cert_pem.c_str();
    opts.tls_private_key_pem = Leaf().key_pem.c_str();
    SG_Server* server = nullptr;

    // Conditions this build cannot evaluate are refused, not ignored.
    opts.integrity_reject_mask = 1u << 20;
    SG_EXPECT_STATUS(SG_Server_Create(&opts, &server), SG_NOT_SUPPORTED);
    opts.integrity_reject_mask = 0;

    // An all-zero allowlist entry would match every failed hash.
    const SG_Sha256 zero{};
    opts.allowed_executables = &zero;
    opts.allowed_executable_count = 1;
    SG_EXPECT_STATUS(SG_Server_Create(&opts, &server), SG_INVALID_ARGUMENT);
    opts.allowed_executables = nullptr;
    opts.allowed_executable_count = 0;

    // Fields a newer header appended must be zero if this build ignores them.
    struct Newer {
        SG_ServerOptions options;
        uint64_t future_field;
    } newer{};
    newer.options = opts;
    newer.options.size = sizeof(newer);
    newer.future_field = 1;
    SG_EXPECT_STATUS(SG_Server_Create(&newer.options, &server), SG_NOT_SUPPORTED);
    newer.future_field = 0;
    SG_ASSERT_OK(SG_Server_Create(&newer.options, &server));
    SG_Server_Destroy(server);

    struct NewerClient {
        SG_ClientConfig config;
        uint64_t future_field;
    } client_cfg{};
    SG_ClientConfig_Init(&client_cfg.config);
    client_cfg.config.size = sizeof(client_cfg);
    client_cfg.config.identity_name = "tail-app";
    client_cfg.config.key_store_type = SG_KEYSTORE_MEMORY;
    client_cfg.future_field = 7;
    SG_Client* client = nullptr;
    SG_EXPECT_STATUS(SG_Client_Create(&client_cfg.config, &client), SG_NOT_SUPPORTED);
    client_cfg.future_field = 0;
    SG_ASSERT_OK(SG_Client_Create(&client_cfg.config, &client));
    SG_Client_Destroy(client);
}
