// Phase 5: end-to-end sessions through the public C APIs of both libraries
// (real sockets, TLS 1.3, authentication, protected frames, lifecycle).
#include "sg_test.h"

#include "support/e2e_harness.h"
#include "support/test_pki.h"
#include "transport/tcp_transport.h"

#include <sockgate/client.h>
#include <sockgate/server.h>

#include "sockgate_common/core/clock.h"
#include "sockgate_common/crypto/crypto.h"

#include <atomic>
#include <chrono>
#include <condition_variable>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <filesystem>
#include <functional>
#include <future>
#include <mutex>
#include <string>
#include <thread>
#include <vector>

using namespace sgtest;

SG_TEST(Session, EndToEndEchoWithRequestIds)
{
    TestServer server;
    server.Start();
    ClientPtr client(NewClient());
    server.Register(client.get());
    ConnectAndAuth(client.get(), server.port);
    SG_EXPECT_EQ(StateOf(client.get()), SG_CLIENT_STATE_ACTIVE);

    uint64_t request_id = 0;
    SG_ASSERT_OK(SG_Client_SendEx(client.get(), "hello", 5, 0, &request_id));
    SG_EXPECT(request_id != 0);
    SG_MessageInfo info;
    SG_MessageInfo_Init(&info);
    SG_EXPECT_EQ(ReceiveText(client.get(), 5000, &info), std::string("hello"));
    SG_EXPECT_EQ(info.request_id, request_id);
    SG_EXPECT(info.flags & SG_MESSAGE_FLAG_RESPONSE);

    SG_ClientSessionInfo si;
    SG_ClientSessionInfo_Init(&si);
    SG_ASSERT_OK(SG_Client_GetSessionInfo(client.get(), &si));
    SG_EXPECT_EQ(si.policy, SG_SESSION_POLICY_NORMAL);
    SG_EXPECT_EQ(std::string(si.tls_protocol), std::string("TLSv1.3"));
    SG_EXPECT(si.expires_in_ms > 0);

    SG_ASSERT(server.WaitOpened(1));
    SG_ServerSessionInfo ss;
    SG_ServerSessionInfo_Init(&ss);
    SG_ASSERT_OK(SG_Server_GetSessionInfo(server.server, server.opened[0], &ss));
    SG_EXPECT(std::memcmp(ss.session_id.bytes, si.session_id.bytes, SG_SESSION_ID_SIZE) == 0);
    SG_EXPECT_EQ(std::string(ss.peer_address).rfind("127.0.0.1:", 0), size_t{0});

    SG_ASSERT_OK(SG_Client_Ping(client.get()));
    SG_ASSERT_OK(SG_Client_Send(client.get(), "after-ping", 10));
    SG_EXPECT_EQ(ReceiveText(client.get()), std::string("after-ping"));

    SG_ASSERT_OK(SG_Client_Disconnect(client.get()));
    SG_EXPECT_EQ(StateOf(client.get()), SG_CLIENT_STATE_CLOSED);
    SG_ASSERT(server.WaitClosed(1));
    SG_EXPECT_EQ(server.closed[0].first, server.opened[0]);
}

SG_TEST(Session, ReconnectRepeatedly)
{
    TestServer server;
    server.Start();
    ClientPtr client(NewClient());
    server.Register(client.get());
    for (int i = 0; i < 3; ++i) {
        ConnectAndAuth(client.get(), server.port);
        const std::string msg = "round-" + std::to_string(i);
        SG_ASSERT_OK(SG_Client_Send(client.get(), msg.data(), msg.size()));
        SG_EXPECT_EQ(ReceiveText(client.get()), msg);
        SG_ASSERT_OK(SG_Client_Disconnect(client.get()));
    }
    SG_EXPECT(server.WaitClosed(3));
}

SG_TEST(Session, EnrollmentThroughIssuedToken)
{
    TestServer server;
    server.configure = [](SG_ServerOptions& o) { o.flags |= SG_SERVER_OPT_ALLOW_ENROLLMENT; };
    server.Start();

    SG_EnrollmentTokenRequest req;
    SG_EnrollmentTokenRequest_Init(&req);
    req.product_id = "e2e-product";
    req.license_id = "LIC-E2E";
    char token[1024];
    size_t written = 0;
    SG_ASSERT_OK(SG_Server_IssueEnrollmentToken(server.server, &req, token, sizeof(token), &written));
    SG_EXPECT(written > 10);
    char tiny[4];
    SG_EXPECT_STATUS(SG_Server_IssueEnrollmentToken(server.server, &req, tiny, sizeof(tiny), &written),
                     SG_BUFFER_TOO_SMALL);

    ClientPtr client(NewClient());
    const SG_ServerConfig t = Target(server.port);
    SG_ASSERT_OK(SG_Client_Connect(client.get(), &t));
    SG_ASSERT_OK(SG_Client_Enroll(client.get(), token));
    SG_ASSERT_OK(SG_Client_Send(client.get(), "enrolled", 8));
    SG_EXPECT_EQ(ReceiveText(client.get()), std::string("enrolled"));
    SG_ASSERT_OK(SG_Client_Disconnect(client.get()));

    // The enrolled installation now authenticates normally...
    ConnectAndAuth(client.get(), server.port);
    SG_ASSERT_OK(SG_Client_Disconnect(client.get()));

    // ...and the token cannot be used again by another installation.
    ClientPtr other(NewClient(ClientOptions(), "other-app"));
    SG_ASSERT_OK(SG_Client_Connect(other.get(), &t));
    SG_EXPECT_STATUS(SG_Client_Enroll(other.get(), token), SG_SERVER_REJECTED);
}

SG_TEST(Session, UnregisteredClientRejected)
{
    TestServer server;
    server.Start();
    ClientPtr client(NewClient());
    SG_ASSERT_OK(SG_Client_EnsureIdentity(client.get(), nullptr));
    const SG_ServerConfig t = Target(server.port);
    SG_ASSERT_OK(SG_Client_Connect(client.get(), &t));
    SG_EXPECT_STATUS(SG_Client_Authenticate(client.get()), SG_SERVER_REJECTED);
    SG_EXPECT_EQ(StateOf(client.get()), SG_CLIENT_STATE_CLOSED);
    SG_EXPECT_STATUS(SG_Client_Send(client.get(), "x", 1), SG_CLOSED);

    SG_ServerStats stats;
    SG_ServerStats_Init(&stats);
    SG_ASSERT_OK(SG_Server_GetStats(server.server, &stats));
    SG_EXPECT_EQ(stats.auth_failed, uint64_t{1});
}

SG_TEST(Session, ServerAuthenticationAndPinning)
{
    TestServer server;
    server.Start();
    ClientPtr client(NewClient());
    server.Register(client.get());

    const TestCert other_ca = CreateRootCa("Not the server's CA");
    SG_ServerConfig t = Target(server.port);
    t.ca_pem = other_ca.cert_pem.c_str();
    SG_EXPECT_STATUS(SG_Client_Connect(client.get(), &t), SG_CERTIFICATE_ERROR);

    t = Target(server.port);
    t.server_name = "wrong.example";
    SG_EXPECT_STATUS(SG_Client_Connect(client.get(), &t), SG_CERTIFICATE_ERROR);

    SG_Sha256 wrong_pin;
    std::memcpy(wrong_pin.bytes, other_ca.spki_sha256.data(), 32);
    t = Target(server.port);
    t.spki_pins = &wrong_pin;
    t.spki_pin_count = 1;
    SG_EXPECT_STATUS(SG_Client_Connect(client.get(), &t), SG_PINNING_ERROR);

    SG_Sha256 pins[2];
    std::memcpy(pins[0].bytes, other_ca.spki_sha256.data(), 32);
    SG_ASSERT_OK(SG_Client_ComputeSpkiPin(Leaf().cert_pem.c_str(), 0, &pins[1]));
    t.spki_pins = pins;
    t.spki_pin_count = 2;
    SG_ASSERT_OK(SG_Client_Connect(client.get(), &t));
    SG_ASSERT_OK(SG_Client_Authenticate(client.get()));
    SG_ASSERT_OK(SG_Client_Disconnect(client.get()));

    // Trusting the OS store without any pin or proof key needs an explicit opt-out.
    SG_ServerConfig sys;
    SG_ServerConfig_Init(&sys);
    sys.host = "127.0.0.1";
    sys.port = server.port;
    sys.flags = SG_TRUST_SYSTEM_STORE;
    SG_EXPECT_STATUS(SG_Client_Connect(client.get(), &sys), SG_INVALID_ARGUMENT);
}

SG_TEST(Session, ApiStateMachineAndArguments)
{
    TestServer server;
    server.Start();
    ClientPtr client(NewClient());
    char buf[8];
    size_t n = 0;
    SG_EXPECT_STATUS(SG_Client_Send(client.get(), "x", 1), SG_INVALID_STATE);
    SG_EXPECT_STATUS(SG_Client_Receive(client.get(), buf, sizeof(buf), &n), SG_INVALID_STATE);
    SG_EXPECT_STATUS(SG_Client_Authenticate(client.get()), SG_INVALID_STATE);
    SG_EXPECT_STATUS(SG_Client_Refresh(client.get()), SG_INVALID_STATE);
    SG_EXPECT_STATUS(SG_Client_Send(nullptr, "x", 1), SG_INVALID_ARGUMENT);
    SG_EXPECT_STATUS(SG_Client_Send(client.get(), nullptr, 3), SG_INVALID_ARGUMENT);

    server.Register(client.get());
    const SG_ServerConfig t = Target(server.port);
    SG_ASSERT_OK(SG_Client_Connect(client.get(), &t));
    SG_EXPECT_STATUS(SG_Client_Connect(client.get(), &t), SG_INVALID_STATE);
    SG_EXPECT_STATUS(SG_Client_Send(client.get(), "x", 1), SG_INVALID_STATE);  // not yet authenticated
    SG_ASSERT_OK(SG_Client_Authenticate(client.get()));
    SG_EXPECT_STATUS(SG_Client_Authenticate(client.get()), SG_INVALID_STATE);
    SG_EXPECT_STATUS(SG_Client_DeleteIdentity(client.get()), SG_INVALID_STATE);

    // Poll with no data: timeout, session stays usable.
    SG_EXPECT_STATUS(SG_Client_ReceiveEx(client.get(), buf, sizeof(buf), &n, nullptr, 0), SG_TIMEOUT);
    SG_EXPECT_EQ(StateOf(client.get()), SG_CLIENT_STATE_ACTIVE);

    // Invalid config structures.
    SG_ClientConfig bad;
    SG_ClientConfig_Init(&bad);
    SG_Client* c2 = nullptr;
    SG_EXPECT_STATUS(SG_Client_Create(&bad, &c2), SG_INVALID_ARGUMENT);  // no identity name
    bad.identity_name = "../../etc/passwd";
    SG_EXPECT_STATUS(SG_Client_Create(&bad, &c2), SG_INVALID_ARGUMENT);
    bad.identity_name = "ok";
    bad.key_store_type = 77;
    SG_EXPECT_STATUS(SG_Client_Create(&bad, &c2), SG_INVALID_ARGUMENT);
    SG_EXPECT(c2 == nullptr);
    SG_EXPECT_EQ(SG_Client_GetApiVersion(), static_cast<uint32_t>(SOCKGATE_API_VERSION));
}

SG_TEST(Session, BufferTooSmallKeepsMessage)
{
    TestServer server;
    server.Start();
    ClientPtr client(NewClient());
    server.Register(client.get());
    ConnectAndAuth(client.get(), server.port);
    const std::string msg(1000, 'q');
    SG_ASSERT_OK(SG_Client_Send(client.get(), msg.data(), msg.size()));
    char small[10];
    size_t needed = 0;
    SG_EXPECT_STATUS(SG_Client_ReceiveEx(client.get(), small, sizeof(small), &needed, nullptr, 5000),
                     SG_BUFFER_TOO_SMALL);
    SG_EXPECT_EQ(needed, msg.size());
    std::vector<char> big(needed);
    size_t n = 0;
    SG_ASSERT_OK(SG_Client_Receive(client.get(), big.data(), big.size(), &n));
    SG_EXPECT(std::string(big.data(), n) == msg);
}

SG_TEST(Session, PayloadLimits)
{
    TestServer server;
    server.configure = [](SG_ServerOptions& o) { o.max_payload_size = 1024; };
    server.Start();
    ClientOptions co;
    co.max_payload = 4096;
    ClientPtr client(NewClient(co));
    server.Register(client.get());
    ConnectAndAuth(client.get(), server.port);

    const std::string too_big_for_client(4097, 'x');
    SG_EXPECT_STATUS(SG_Client_Send(client.get(), too_big_for_client.data(), too_big_for_client.size()),
                     SG_INVALID_ARGUMENT);
    // Larger than the server accepts: the server closes the session.
    const std::string too_big_for_server(2000, 'y');
    SG_ASSERT_OK(SG_Client_Send(client.get(), too_big_for_server.data(), too_big_for_server.size()));
    char buf[16];
    size_t n = 0;
    const SG_Status st = SG_Client_ReceiveEx(client.get(), buf, sizeof(buf), &n, nullptr, 5000);
    SG_EXPECT(st == SG_CLOSED || st == SG_NETWORK_ERROR);
    SG_EXPECT(server.WaitClosed(1));
}

SG_TEST(Session, SessionExpiry)
{
    TestServer server;
    server.configure = [](SG_ServerOptions& o) { o.session_lifetime_ms = 1200; };
    server.Start();
    ClientPtr client(NewClient());
    server.Register(client.get());
    ConnectAndAuth(client.get(), server.port);
    char buf[16];
    size_t n = 0;
    const SG_Status st = SG_Client_ReceiveEx(client.get(), buf, sizeof(buf), &n, nullptr, 8000);
    SG_EXPECT_STATUS(st, SG_SESSION_EXPIRED);
    SG_EXPECT_EQ(StateOf(client.get()), SG_CLIENT_STATE_EXPIRED);
    SG_EXPECT_STATUS(SG_Client_Send(client.get(), "late", 4), SG_SESSION_EXPIRED);
    SG_ASSERT(server.WaitClosed(1));
    SG_EXPECT_STATUS(server.closed[0].second, SG_SESSION_EXPIRED);
}

SG_TEST(Session, IdleTimeout)
{
    TestServer server;
    server.configure = [](SG_ServerOptions& o) { o.idle_timeout_ms = 600; };
    server.Start();
    ClientPtr client(NewClient());
    server.Register(client.get());
    ConnectAndAuth(client.get(), server.port);
    char buf[16];
    size_t n = 0;
    const auto start = std::chrono::steady_clock::now();
    const SG_Status st = SG_Client_ReceiveEx(client.get(), buf, sizeof(buf), &n, nullptr, 8000);
    const auto ms = std::chrono::duration_cast<std::chrono::milliseconds>(std::chrono::steady_clock::now() - start).count();
    SG_EXPECT_STATUS(st, SG_CLOSED);
    SG_EXPECT(ms < 5000);
}

SG_TEST(Session, RefreshWhileTrafficFlows)
{
    TestServer server;
    server.echo = false;
    server.configure = [](SG_ServerOptions& o) { o.min_reauth_interval_ms = 1; };
    server.Start();
    ClientPtr client(NewClient());
    server.Register(client.get());
    ConnectAndAuth(client.get(), server.port);
    SG_ASSERT(server.WaitOpened(1));
    const SG_SessionHandle handle = server.opened[0];

    // The server streams numbered messages while the client refreshes and
    // keeps sending: frames in flight across the epoch switch must survive.
    std::atomic<bool> stop{false};
    struct Joiner {
        std::atomic<bool>& stop;
        std::thread& thread;
        ~Joiner()
        {
            stop = true;
            if (thread.joinable()) thread.join();
        }
    };
    std::thread pusher;
    Joiner joiner{stop, pusher};
    pusher = std::thread([&]() {
        for (int i = 0; !stop.load() && i < 5000; ++i) {
            const std::string m = "s" + std::to_string(i);
            if (SG_Server_Send(server.server, handle, m.data(), m.size()) != SG_OK) break;
            std::this_thread::sleep_for(std::chrono::microseconds(200));
        }
    });

    for (int round = 0; round < 3; ++round) {
        for (int k = 0; k < 20; ++k) SG_ASSERT_OK(SG_Client_Send(client.get(), "c", 1));
        // The server enforces min_reauth_interval_ms (1 ms here) with
        // millisecond timestamps; on loopback a refresh can otherwise land in
        // the same millisecond as the previous one and be rejected.
        std::this_thread::sleep_for(std::chrono::milliseconds(5));
        SG_ASSERT_OK(SG_Client_Refresh(client.get()));
    }
    SG_ClientSessionInfo si;
    SG_ClientSessionInfo_Init(&si);
    SG_ASSERT_OK(SG_Client_GetSessionInfo(client.get(), &si));
    SG_EXPECT_EQ(si.epoch, 3u);

    // Everything the server pushed arrives in order, across all epochs.
    int expected = 0;
    for (int i = 0; i < 200; ++i) {
        const std::string m = ReceiveText(client.get(), 5000);
        SG_ASSERT_EQ(m, "s" + std::to_string(expected));
        ++expected;
    }
    stop = true;
    if (pusher.joinable()) pusher.join();
    SG_ASSERT_OK(SG_Client_Send(client.get(), "done", 4));
    for (int i = 0; i < 200; ++i) {
        std::lock_guard<std::mutex> lock(server.mutex);
        if (!server.messages.empty() && server.messages.back() == "done") break;
    }
    SG_EXPECT_EQ(StateOf(client.get()), SG_CLIENT_STATE_ACTIVE);
}

SG_TEST(Session, RefreshRateLimited)
{
    TestServer server;
    server.configure = [](SG_ServerOptions& o) { o.min_reauth_interval_ms = 60000; };
    server.Start();
    ClientPtr client(NewClient());
    server.Register(client.get());
    ConnectAndAuth(client.get(), server.port);
    const SG_Status st = SG_Client_Refresh(client.get());
    SG_EXPECT(st != SG_OK);
    SG_EXPECT_EQ(StateOf(client.get()), SG_CLIENT_STATE_CLOSED);
}

SG_TEST(Session, RevocationClosesLiveSession)
{
    TestServer server;
    server.Start();
    ClientPtr client(NewClient());
    server.Register(client.get());
    ConnectAndAuth(client.get(), server.port);
    SG_IdentityInfo id;
    SG_IdentityInfo_Init(&id);
    SG_ASSERT_OK(SG_Client_GetIdentity(client.get(), &id));

    SG_ASSERT_OK(SG_Server_RevokeClient(server.server, &id.installation_id));
    char buf[16];
    size_t n = 0;
    SG_EXPECT_STATUS(SG_Client_ReceiveEx(client.get(), buf, sizeof(buf), &n, nullptr, 5000), SG_SERVER_REJECTED);
    const SG_ServerConfig t = Target(server.port);
    SG_ASSERT_OK(SG_Client_Connect(client.get(), &t));
    SG_EXPECT_STATUS(SG_Client_Authenticate(client.get()), SG_SERVER_REJECTED);
}

SG_TEST(Session, RevocationTakesEffectWhenStorageFails)
{
    namespace fs = std::filesystem;
    const fs::path dir = fs::temp_directory_path() / ("sockgate-e2e-registry-io-" + std::to_string(sg::MonotonicMs()));
    fs::create_directories(dir);
    const std::string registry_path = (dir / "registry.bin").string();
    TestServer server;
    server.configure = [&](SG_ServerOptions& o) { o.registry_path = registry_path.c_str(); };
    server.Start();
    ClientPtr client(NewClient());
    server.Register(client.get());
    ConnectAndAuth(client.get(), server.port);
    SG_IdentityInfo id;
    SG_IdentityInfo_Init(&id);
    SG_ASSERT_OK(SG_Client_GetIdentity(client.get(), &id));

    fs::remove_all(dir);  // the revocation cannot be persisted...
    SG_EXPECT_STATUS(SG_Server_RevokeClient(server.server, &id.installation_id), SG_STORAGE_ERROR);
    // ...but the live session is closed and the installation is refused.
    char buf[16];
    size_t n = 0;
    SG_EXPECT_STATUS(SG_Client_ReceiveEx(client.get(), buf, sizeof(buf), &n, nullptr, 5000), SG_SERVER_REJECTED);
    const SG_ServerConfig t = Target(server.port);
    SG_ASSERT_OK(SG_Client_Connect(client.get(), &t));
    SG_EXPECT_STATUS(SG_Client_Authenticate(client.get()), SG_SERVER_REJECTED);
}

SG_TEST(Session, ConcurrentSendersAndReceiver)
{
    TestServer server;
    server.Start();
    ClientPtr client(NewClient());
    server.Register(client.get());
    ConnectAndAuth(client.get(), server.port);

    constexpr int kThreads = 4;
    constexpr int kPerThread = 150;
    std::atomic<int> received{0};
    std::thread receiver([&]() {
        char buf[256];
        while (received.load() < kThreads * kPerThread) {
            size_t n = 0;
            if (SG_Client_ReceiveEx(client.get(), buf, sizeof(buf), &n, nullptr, 10000) != SG_OK) break;
            received.fetch_add(1);
        }
    });
    std::vector<std::thread> senders;
    std::atomic<int> send_errors{0};
    for (int t = 0; t < kThreads; ++t) {
        senders.emplace_back([&, t]() {
            for (int i = 0; i < kPerThread; ++i) {
                const std::string m = std::to_string(t) + ":" + std::to_string(i);
                if (SG_Client_Send(client.get(), m.data(), m.size()) != SG_OK) send_errors.fetch_add(1);
            }
        });
    }
    for (auto& s : senders) s.join();
    receiver.join();
    SG_EXPECT_EQ(send_errors.load(), 0);
    SG_EXPECT_EQ(received.load(), kThreads * kPerThread);
    SG_EXPECT_EQ(StateOf(client.get()), SG_CLIENT_STATE_ACTIVE);
}

SG_TEST(Session, DisconnectWakesBlockedReceive)
{
    TestServer server;
    server.Start();
    ClientPtr client(NewClient());
    server.Register(client.get());
    ConnectAndAuth(client.get(), server.port);
    auto blocked = std::async(std::launch::async, [&]() {
        char buf[16];
        size_t n = 0;
        return SG_Client_ReceiveEx(client.get(), buf, sizeof(buf), &n, nullptr, SG_WAIT_INFINITE);
    });
    std::this_thread::sleep_for(std::chrono::milliseconds(150));
    SG_ASSERT_OK(SG_Client_Disconnect(client.get()));
    SG_ASSERT(blocked.wait_for(std::chrono::seconds(5)) == std::future_status::ready);
    const SG_Status st = blocked.get();
    SG_EXPECT(st == SG_CLOSED || st == SG_NETWORK_ERROR);
}

SG_TEST(Session, ServerStopClosesClients)
{
    TestServer server;
    server.Start();
    ClientPtr client(NewClient());
    server.Register(client.get());
    ConnectAndAuth(client.get(), server.port);
    SG_ASSERT_OK(SG_Server_Stop(server.server));
    char buf[16];
    size_t n = 0;
    const SG_Status st = SG_Client_ReceiveEx(client.get(), buf, sizeof(buf), &n, nullptr, 5000);
    SG_EXPECT(st == SG_CLOSED || st == SG_NETWORK_ERROR);
    SG_EXPECT(server.WaitClosed(1));
}

SG_TEST(Session, ApplicationLayerEncryptionPolicy)
{
    TestServer server;
    server.configure = [](SG_ServerOptions& o) { o.flags |= SG_SERVER_OPT_REQUIRE_APP_ENCRYPTION; };
    server.Start();

    ClientOptions enc;
    enc.flags = SG_CLIENT_FLAG_APP_ENCRYPTION;
    ClientPtr good(NewClient(enc, "enc-app"));
    server.Register(good.get());
    ConnectAndAuth(good.get(), server.port);
    SG_ASSERT_OK(SG_Client_Send(good.get(), "sealed", 6));
    SG_MessageInfo info;
    SG_MessageInfo_Init(&info);
    SG_EXPECT_EQ(ReceiveText(good.get(), 5000, &info), std::string("sealed"));
    SG_EXPECT(info.flags & SG_MESSAGE_FLAG_ENCRYPTED);

    ClientPtr plain(NewClient(ClientOptions(), "plain-app"));
    server.Register(plain.get());
    ConnectAndAuth(plain.get(), server.port);
    SG_ASSERT_OK(SG_Client_Send(plain.get(), "clear", 5));
    char buf[16];
    size_t n = 0;
    SG_EXPECT_STATUS(SG_Client_ReceiveEx(plain.get(), buf, sizeof(buf), &n, nullptr, 5000), SG_CLOSED);
}

SG_TEST(Session, SilentAndExcessConnectionsAreDropped)
{
    TestServer server;
    server.configure = [](SG_ServerOptions& o) {
        o.handshake_timeout_ms = 500;
        o.max_connections = 1;
    };
    server.Start();
    sg::client::TcpTransportOptions opts;
    opts.io_timeout_ms = 5000;
    sg::client::TcpTransport silent(opts);
    SG_ASSERT_OK(silent.Connect({"127.0.0.1", server.port}));
    std::this_thread::sleep_for(std::chrono::milliseconds(100));

    // Second connection exceeds max_connections and is closed at once.
    sg::client::TcpTransport excess(opts);
    SG_ASSERT_OK(excess.Connect({"127.0.0.1", server.port}));
    uint8_t b = 0;
    size_t n = 0;
    const sg::Status ex = excess.ReceiveFor(&b, 1, &n, 3000);
    SG_EXPECT(ex == SG_CLOSED || ex == SG_NETWORK_ERROR);

    // The silent one is dropped after the handshake timeout.
    const auto start = std::chrono::steady_clock::now();
    const sg::Status st = silent.ReceiveFor(&b, 1, &n, 5000);
    const auto ms = std::chrono::duration_cast<std::chrono::milliseconds>(std::chrono::steady_clock::now() - start).count();
    SG_EXPECT(st == SG_CLOSED || st == SG_NETWORK_ERROR);
    SG_EXPECT(ms < 4000);
}

SG_TEST(Session, AuthorizeCallbackDecides)
{
    TestServer server;
    std::atomic<int> calls{0};
    bool deny = false;
    server.authorize = [&](const SG_AuthRequest* r, SG_AuthDecision* d) {
        calls.fetch_add(1);
        SG_EXPECT_EQ(std::string(r->product_id), std::string("e2e-product"));
        if (deny) {
            d->allow = 0;
        } else {
            d->policy = SG_SESSION_POLICY_RESTRICTED;
            d->granted_features = 0x5;
        }
        return SG_OK;
    };
    server.Start();
    ClientPtr client(NewClient());
    server.Register(client.get());
    ConnectAndAuth(client.get(), server.port);
    SG_ClientSessionInfo si;
    SG_ClientSessionInfo_Init(&si);
    SG_ASSERT_OK(SG_Client_GetSessionInfo(client.get(), &si));
    SG_EXPECT_EQ(si.policy, SG_SESSION_POLICY_RESTRICTED);
    SG_EXPECT_EQ(si.granted_features, uint64_t{5});
    SG_ASSERT_OK(SG_Client_Disconnect(client.get()));

    deny = true;
    const SG_ServerConfig t = Target(server.port);
    SG_ASSERT_OK(SG_Client_Connect(client.get(), &t));
    SG_EXPECT_STATUS(SG_Client_Authenticate(client.get()), SG_SERVER_REJECTED);
    SG_EXPECT_EQ(calls.load(), 2);
}

SG_TEST(Session, ServerProofKey)
{
    const TestCert proof = IssueLocalhostServer(Ca());  // any P-256 key pair
    std::unique_ptr<sg::crypto::SoftwareP256Key> key;
    SG_ASSERT_OK(sg::crypto::SoftwareP256Key::FromPem(
        sg::ByteView(reinterpret_cast<const uint8_t*>(proof.key_pem.data()), proof.key_pem.size()), &key));
    SG_PublicKey proof_pub;
    sg::crypto::P256PublicKey pub;
    SG_ASSERT_OK(key->PublicKey(&pub));
    std::memcpy(proof_pub.bytes, pub.data(), pub.size());

    TestServer server;
    server.configure = [&](SG_ServerOptions& o) { o.proof_key_pem = proof.key_pem.c_str(); };
    server.Start();
    ClientPtr client(NewClient());
    server.Register(client.get());

    SG_ServerConfig t = Target(server.port);
    t.proof_keys = &proof_pub;
    t.proof_key_count = 1;
    SG_ASSERT_OK(SG_Client_Connect(client.get(), &t));
    SG_ASSERT_OK(SG_Client_Authenticate(client.get()));
    SG_ASSERT_OK(SG_Client_Disconnect(client.get()));

    SG_PublicKey wrong = proof_pub;
    std::unique_ptr<sg::crypto::SoftwareP256Key> other;
    SG_ASSERT_OK(sg::crypto::SoftwareP256Key::Generate(&other));
    SG_ASSERT_OK(other->PublicKey(&pub));
    std::memcpy(wrong.bytes, pub.data(), pub.size());
    t.proof_keys = &wrong;
    SG_ASSERT_OK(SG_Client_Connect(client.get(), &t));
    SG_EXPECT_STATUS(SG_Client_Authenticate(client.get()), SG_INVALID_SIGNATURE);
}

SG_TEST(Session, CallbacksMayReenterServerApi)
{
    // on_authorize runs without internal locks: calling back into the server
    // API for the very session being authorised must not deadlock.
    TestServer server;
    std::atomic<int> reentered{0};
    server.authorize = [&](const SG_AuthRequest* r, SG_AuthDecision*) {
        SG_ServerStats stats;
        SG_ServerStats_Init(&stats);
        if (SG_Server_GetStats(server.server, &stats) == SG_OK) reentered.fetch_add(1);
        SG_ServerSessionInfo info;
        SG_ServerSessionInfo_Init(&info);
        (void)SG_Server_GetSessionInfo(server.server, r->session, &info);  // not open yet: NOT_FOUND
        (void)SG_Server_Send(server.server, r->session, "x", 1);          // not open yet: refused
        return SG_OK;
    };
    server.Start();
    ClientPtr client(NewClient());
    server.Register(client.get());
    ConnectAndAuth(client.get(), server.port);
    SG_EXPECT_EQ(reentered.load(), 1);
    SG_ASSERT_OK(SG_Client_Send(client.get(), "ok", 2));
    SG_EXPECT_EQ(ReceiveText(client.get()), std::string("ok"));
}

SG_TEST(Session, ReplyToUnknownRequestIsRejectedLocally)
{
    TestServer server;
    server.Start();
    ClientPtr client(NewClient());
    server.Register(client.get());
    ConnectAndAuth(client.get(), server.port);
    // Replying to a request the server never sent would make the server drop
    // the session; the library refuses it before anything is sent.
    SG_EXPECT_STATUS(SG_Client_SendEx(client.get(), "r", 1, 12345, nullptr), SG_INVALID_ARGUMENT);
    SG_EXPECT_EQ(StateOf(client.get()), SG_CLIENT_STATE_ACTIVE);
    SG_ASSERT_OK(SG_Client_Send(client.get(), "still-alive", 11));
    SG_EXPECT_EQ(ReceiveText(client.get()), std::string("still-alive"));
}

SG_TEST(Session, AutoRefreshKeepsSessionAlive)
{
    TestServer server;
    server.configure = [](SG_ServerOptions& o) {
        o.session_lifetime_ms = 1500;
        o.min_reauth_interval_ms = 1;
    };
    server.Start();
    ClientOptions co;
    co.flags = SG_CLIENT_FLAG_AUTO_REFRESH;
    ClientPtr client(NewClient(co));
    server.Register(client.get());
    ConnectAndAuth(client.get(), server.port);
    // Traffic for well over one lifetime: refreshes happen at 80% of it.
    const auto end = std::chrono::steady_clock::now() + std::chrono::milliseconds(4000);
    int rounds = 0;
    while (std::chrono::steady_clock::now() < end) {
        SG_ASSERT_OK(SG_Client_Send(client.get(), "tick", 4));
        SG_ASSERT_EQ(ReceiveText(client.get()), std::string("tick"));
        std::this_thread::sleep_for(std::chrono::milliseconds(50));
        ++rounds;
    }
    SG_ClientSessionInfo si;
    SG_ClientSessionInfo_Init(&si);
    SG_ASSERT_OK(SG_Client_GetSessionInfo(client.get(), &si));
    SG_EXPECT(si.epoch >= 2);
    SG_EXPECT_EQ(si.state, SG_CLIENT_STATE_ACTIVE);
    SG_EXPECT(rounds > 20);
}
