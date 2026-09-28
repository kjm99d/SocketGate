// Phase 6: proxies and MITM. Proxies only relay ciphertext; a TLS-terminating
// MITM with a CA the victim wrongly trusts is stopped by pinning, by the
// channel-bound client proof (server side) and by the server proof key.
#include "sg_test.h"

#include "support/test_pki.h"
#include "support/test_proxy.h"
#include "transport/proxy.h"

#include <sockgate/client.h>
#include <sockgate/server.h>

#include <chrono>
#include <cstring>
#include <future>
#include <string>
#include <thread>

using namespace sgtest;

namespace {

const TestCert& RealCa()
{
    static const TestCert ca = CreateRootCa("Real Server CA");
    return ca;
}
const TestCert& RealLeaf()
{
    static const TestCert leaf = IssueLocalhostServer(RealCa());
    return leaf;
}
const TestCert& EvilCa()
{
    static const TestCert ca = CreateRootCa("User-installed interception CA");
    return ca;
}
const TestCert& EvilLeaf()
{
    static const TestCert leaf = IssueLocalhostServer(EvilCa());
    return leaf;
}

struct Server {
    SG_Server* server = nullptr;
    uint16_t port = 0;
    ~Server()
    {
        if (server != nullptr) SG_Server_Destroy(server);
    }
    void Start(const TestCert& leaf = RealLeaf(), const char* proof_key_pem = nullptr)
    {
        SG_ServerCallbacks cb;
        SG_ServerCallbacks_Init(&cb);
        cb.user = this;
        cb.on_message = [](void* user, SG_SessionHandle s, const void* data, size_t size, const SG_MessageInfo* info) {
            SG_Server_SendEx(static_cast<Server*>(user)->server, s, data, size, info->request_id);
        };
        SG_ServerOptions opts;
        SG_ServerOptions_Init(&opts);
        opts.bind_address = "127.0.0.1";
        opts.tls_cert_chain_pem = leaf.cert_pem.c_str();
        opts.tls_private_key_pem = leaf.key_pem.c_str();
        opts.proof_key_pem = proof_key_pem;
        opts.callbacks = &cb;
        SG_ASSERT_OK(SG_Server_Create(&opts, &server));
        SG_ASSERT_OK(SG_Server_Start(server));
        SG_ASSERT_OK(SG_Server_GetPort(server, &port));
    }
    void Register(SG_Client* c)
    {
        SG_IdentityInfo id;
        SG_IdentityInfo_Init(&id);
        SG_ASSERT_OK(SG_Client_EnsureIdentity(c, &id));
        SG_ClientRecord rec;
        SG_ClientRecord_Init(&rec);
        rec.public_key = id.public_key;
        SG_ASSERT_OK(SG_Server_RegisterClient(server, &rec));
    }
    uint64_t AuthFailures()
    {
        SG_ServerStats stats;
        SG_ServerStats_Init(&stats);
        SG_Server_GetStats(server, &stats);
        return stats.auth_failed;
    }
};

struct ClientDeleter {
    void operator()(SG_Client* c) const { SG_Client_Destroy(c); }
};
using ClientPtr = std::unique_ptr<SG_Client, ClientDeleter>;

ClientPtr NewClient(const SG_ProxyConfig* proxy = nullptr, const char* identity = "proxy-app")
{
    SG_ClientConfig cfg;
    SG_ClientConfig_Init(&cfg);
    cfg.identity_name = identity;
    cfg.key_store_type = SG_KEYSTORE_MEMORY;
    cfg.proxy = proxy;
    cfg.connect_timeout_ms = 3000;
    cfg.io_timeout_ms = 5000;
    SG_Client* c = nullptr;
    SG_ASSERT_OK(SG_Client_Create(&cfg, &c));
    return ClientPtr(c);
}

SG_ServerConfig Target(uint16_t port, const std::string& ca_pem)
{
    SG_ServerConfig t;
    SG_ServerConfig_Init(&t);
    t.host = "127.0.0.1";
    t.port = port;
    t.ca_pem = ca_pem.c_str();
    return t;
}

SG_ProxyConfig Explicit(uint32_t type, uint16_t port, const char* user = nullptr, const char* pass = nullptr)
{
    SG_ProxyConfig p;
    SG_ProxyConfig_Init(&p);
    p.mode = SG_PROXY_MODE_EXPLICIT;
    p.type = type;
    p.host = "127.0.0.1";
    p.port = port;
    p.username = user;
    p.password = pass;
    return p;
}

void EchoRoundTrip(SG_Client* c, const std::string& msg)
{
    SG_ASSERT_OK(SG_Client_Send(c, msg.data(), msg.size()));
    char buf[256];
    size_t n = 0;
    SG_ASSERT_OK(SG_Client_ReceiveEx(c, buf, sizeof(buf), &n, nullptr, 5000));
    SG_EXPECT(std::string(buf, n) == msg);
}

}  // namespace

SG_TEST(Proxy, TunnelsCarryOnlyCiphertext)
{
    Server server;
    server.Start();
    const std::string secret = "top-secret-payload-0123456789";
    for (auto kind : {TestProxy::Kind::kHttpConnect, TestProxy::Kind::kSocks4a, TestProxy::Kind::kSocks5}) {
        TestProxy::Options po;
        po.kind = kind;
        TestProxy proxy(po);
        const uint32_t type = kind == TestProxy::Kind::kHttpConnect ? SG_PROXY_TYPE_HTTP_CONNECT
                              : kind == TestProxy::Kind::kSocks4a   ? SG_PROXY_TYPE_SOCKS4A
                                                                    : SG_PROXY_TYPE_SOCKS5;
        const SG_ProxyConfig pc = Explicit(type, proxy.port());
        ClientPtr client = NewClient(&pc);
        server.Register(client.get());
        const std::string ca = RealCa().cert_pem;
        const SG_ServerConfig t = Target(server.port, ca);
        SG_ASSERT_OK(SG_Client_Connect(client.get(), &t));
        SG_ASSERT_OK(SG_Client_Authenticate(client.get()));
        EchoRoundTrip(client.get(), secret);
        SG_ASSERT_OK(SG_Client_Disconnect(client.get()));
        SG_EXPECT_EQ(proxy.tunnels(), 1);
        SG_EXPECT_EQ(proxy.last_target(), "127.0.0.1:" + std::to_string(server.port));
        // The proxy saw traffic, but never the plaintext.
        const std::string seen = proxy.captured();
        SG_EXPECT(seen.size() > secret.size());
        SG_EXPECT(seen.find(secret) == std::string::npos);
        SG_EXPECT(seen.find("proxy-app") == std::string::npos);
    }
}

SG_TEST(Proxy, Authentication)
{
    Server server;
    server.Start();
    const std::string ca = RealCa().cert_pem;
    const SG_ServerConfig t = Target(server.port, ca);
    for (auto kind : {TestProxy::Kind::kHttpConnect, TestProxy::Kind::kSocks5}) {
        TestProxy::Options po;
        po.kind = kind;
        po.required_user = "alice";
        po.required_password = "s3cret";
        TestProxy proxy(po);
        const uint32_t type = kind == TestProxy::Kind::kHttpConnect ? SG_PROXY_TYPE_HTTP_CONNECT : SG_PROXY_TYPE_SOCKS5;

        const SG_ProxyConfig good = Explicit(type, proxy.port(), "alice", "s3cret");
        ClientPtr ok_client = NewClient(&good, "auth-ok");
        server.Register(ok_client.get());
        SG_ASSERT_OK(SG_Client_Connect(ok_client.get(), &t));
        SG_ASSERT_OK(SG_Client_Authenticate(ok_client.get()));

        const SG_ProxyConfig bad = Explicit(type, proxy.port(), "alice", "wrong");
        ClientPtr bad_client = NewClient(&bad, "auth-bad");
        SG_EXPECT_STATUS(SG_Client_Connect(bad_client.get(), &t), SG_PROXY_ERROR);

        const SG_ProxyConfig none = Explicit(type, proxy.port());
        ClientPtr anon = NewClient(&none, "auth-none");
        SG_EXPECT_STATUS(SG_Client_Connect(anon.get(), &t), SG_PROXY_ERROR);
    }
}

SG_TEST(Proxy, ConnectTimeoutCoversProxyAndTls)
{
    // A slow proxy in front of a server that never answers the TLS handshake:
    // connect_timeout_ms bounds the whole connect, the handshake does not get
    // a fresh budget after the proxy took most of it.
    TestProxy::Options silent_options;
    silent_options.misbehaviour = TestProxy::Misbehaviour::kSilent;
    TestProxy silent_server(silent_options);  // accepts, reads, never answers
    TestProxy::Options slow_options;
    slow_options.reply_delay_ms = 1200;
    TestProxy slow_proxy(slow_options);
    const SG_ProxyConfig pc = Explicit(SG_PROXY_TYPE_HTTP_CONNECT, slow_proxy.port());

    SG_ClientConfig cfg;
    SG_ClientConfig_Init(&cfg);
    cfg.identity_name = "timeout-app";
    cfg.key_store_type = SG_KEYSTORE_MEMORY;
    cfg.proxy = &pc;
    cfg.connect_timeout_ms = 2000;
    SG_Client* raw = nullptr;
    SG_ASSERT_OK(SG_Client_Create(&cfg, &raw));
    ClientPtr client(raw);
    const std::string ca = RealCa().cert_pem;
    const SG_ServerConfig t = Target(silent_server.port(), ca);
    const auto start = std::chrono::steady_clock::now();
    SG_EXPECT_STATUS(SG_Client_Connect(client.get(), &t), SG_TIMEOUT);
    const auto ms =
        std::chrono::duration_cast<std::chrono::milliseconds>(std::chrono::steady_clock::now() - start).count();
    SG_EXPECT(slow_proxy.tunnels() == 1);  // the proxy part succeeded
    SG_EXPECT(ms >= 1900);                 // ...and the budget was used up
    SG_EXPECT(ms < 2900);                  // a fresh TLS budget would take ~3200 ms
}

SG_TEST(Proxy, DisconnectAbortsConnectWithClosed)
{
    // Disconnect() from another thread cancels a Connect() in any phase; the
    // caller always sees SG_CLOSED, never a proxy or TLS error.
    TestProxy::Options silent_options;
    silent_options.misbehaviour = TestProxy::Misbehaviour::kSilent;
    TestProxy silent_server(silent_options);  // accepts, reads, never answers
    const std::string ca = RealCa().cert_pem;
    const SG_ServerConfig t = Target(silent_server.port(), ca);
    for (int phase = 0; phase < 2; ++phase) {
        // phase 0: stuck in the proxy negotiation; phase 1: stuck in the TLS handshake.
        TestProxy::Options proxy_options;
        proxy_options.reply_delay_ms = phase == 0 ? 3000 : 0;
        TestProxy proxy(proxy_options);
        const SG_ProxyConfig pc = Explicit(SG_PROXY_TYPE_HTTP_CONNECT, proxy.port());
        ClientPtr client = NewClient(&pc);  // connect_timeout 3000 ms
        auto result = std::async(std::launch::async, [&]() { return SG_Client_Connect(client.get(), &t); });
        std::this_thread::sleep_for(std::chrono::milliseconds(400));
        if (phase == 1) {
            // Make sure the proxy part is over, i.e. the client is in the TLS handshake.
            for (int i = 0; i < 100 && proxy.tunnels() == 0; ++i) std::this_thread::sleep_for(std::chrono::milliseconds(20));
            SG_ASSERT(proxy.tunnels() == 1);
            std::this_thread::sleep_for(std::chrono::milliseconds(100));
        }
        const auto start = std::chrono::steady_clock::now();
        SG_Client_Disconnect(client.get());
        SG_ASSERT(result.wait_for(std::chrono::seconds(5)) == std::future_status::ready);
        const auto ms =
            std::chrono::duration_cast<std::chrono::milliseconds>(std::chrono::steady_clock::now() - start).count();
        const SG_Status st = result.get();
        if (st != SG_CLOSED) {
            sgtest::ReportFailure(__FILE__, __LINE__,
                                  std::string("phase ") + std::to_string(phase) + ": " + SG_StatusString(st));
        }
        SG_EXPECT(ms < 1500);  // cancelled, not timed out
        uint32_t state = 0;
        SG_Client_GetState(client.get(), &state);
        SG_EXPECT_EQ(state, SG_CLIENT_STATE_CLOSED);
    }
}

SG_TEST(Proxy, HostileOrBrokenProxies)
{
    Server server;
    server.Start();
    const std::string ca = RealCa().cert_pem;
    const SG_ServerConfig t = Target(server.port, ca);
    struct Case {
        TestProxy::Kind kind;
        TestProxy::Misbehaviour mis;
        uint32_t type;
        SG_Status expected;
    };
    const Case cases[] = {
        {TestProxy::Kind::kHttpConnect, TestProxy::Misbehaviour::kRefuse, SG_PROXY_TYPE_HTTP_CONNECT, SG_PROXY_ERROR},
        {TestProxy::Kind::kHttpConnect, TestProxy::Misbehaviour::kGarbage, SG_PROXY_TYPE_HTTP_CONNECT, SG_PROXY_ERROR},
        {TestProxy::Kind::kHttpConnect, TestProxy::Misbehaviour::kHugeHeader, SG_PROXY_TYPE_HTTP_CONNECT, SG_PROXY_ERROR},
        {TestProxy::Kind::kHttpConnect, TestProxy::Misbehaviour::kSilent, SG_PROXY_TYPE_HTTP_CONNECT, SG_TIMEOUT},
        {TestProxy::Kind::kSocks4a, TestProxy::Misbehaviour::kRefuse, SG_PROXY_TYPE_SOCKS4A, SG_PROXY_ERROR},
        {TestProxy::Kind::kSocks5, TestProxy::Misbehaviour::kRefuse, SG_PROXY_TYPE_SOCKS5, SG_PROXY_ERROR},
    };
    for (const auto& c : cases) {
        TestProxy::Options po;
        po.kind = c.kind;
        po.misbehaviour = c.mis;
        TestProxy proxy(po);
        const SG_ProxyConfig pc = Explicit(c.type, proxy.port());
        ClientPtr client = NewClient(&pc);
        const SG_Status st = SG_Client_Connect(client.get(), &t);
        if (st != c.expected) {
            sgtest::ReportFailure(__FILE__, __LINE__,
                                  std::string("proxy case returned ") + SG_StatusString(st) + ", expected " +
                                      SG_StatusString(c.expected));
        }
        uint32_t state = 0;
        SG_Client_GetState(client.get(), &state);
        SG_EXPECT_EQ(state, SG_CLIENT_STATE_CLOSED);
    }
    // A proxy on a port nobody listens on.
    {
        uint16_t dead_port;
        {
            TestProxy tmp(TestProxy::Options{});
            dead_port = tmp.port();
        }
        const SG_ProxyConfig pc = Explicit(SG_PROXY_TYPE_SOCKS5, dead_port);
        ClientPtr client = NewClient(&pc);
        const SG_Status st = SG_Client_Connect(client.get(), &t);
        SG_EXPECT(st == SG_PROXY_ERROR || st == SG_TIMEOUT);
    }
}

SG_TEST(Mitm, UserInstalledCaCannotRelayAnAuthenticatedSession)
{
    // The victim trusts the interception CA (as if installed by malware or a
    // corporate proxy) and has no pins configured. TLS "works", but the
    // channel-bound client proof fails at the real server.
    Server server;
    server.Start();
    TlsMitmRelay mitm(EvilLeaf(), RealCa(), server.port);
    ClientPtr client = NewClient();
    server.Register(client.get());
    const std::string both = RealCa().cert_pem + EvilCa().cert_pem;
    const SG_ServerConfig t = Target(mitm.port(), both);
    SG_ASSERT_OK(SG_Client_Connect(client.get(), &t));
    SG_EXPECT_STATUS(SG_Client_Authenticate(client.get()), SG_SERVER_REJECTED);
    SG_EXPECT_EQ(mitm.sessions(), 1);
    SG_EXPECT_EQ(server.AuthFailures(), uint64_t{1});
}

SG_TEST(Mitm, PinningStopsInterceptionBeforeAnyData)
{
    Server server;
    server.Start();
    TlsMitmRelay mitm(EvilLeaf(), RealCa(), server.port);
    ClientPtr client = NewClient();
    const std::string both = RealCa().cert_pem + EvilCa().cert_pem;
    SG_ServerConfig t = Target(mitm.port(), both);
    SG_Sha256 pin;
    std::memcpy(pin.bytes, RealLeaf().spki_sha256.data(), 32);
    t.spki_pins = &pin;
    t.spki_pin_count = 1;
    SG_EXPECT_STATUS(SG_Client_Connect(client.get(), &t), SG_PINNING_ERROR);
    SG_EXPECT_EQ(mitm.sessions(), 0);  // the relay never got a TLS session with the client
}

SG_TEST(Mitm, FakeServerDetectedByProofKey)
{
    // An attacker runs its own SockGate server behind a trusted-by-mistake CA
    // and even registers the victim's (public) key. Without a server proof key
    // the victim cannot tell (documented limitation); with one it can.
    const TestCert proof = IssueLocalhostServer(RealCa());
    std::unique_ptr<sg::crypto::SoftwareP256Key> key;
    SG_ASSERT_OK(sg::crypto::SoftwareP256Key::FromPem(
        sg::ByteView(reinterpret_cast<const uint8_t*>(proof.key_pem.data()), proof.key_pem.size()), &key));
    sg::crypto::P256PublicKey pub;
    SG_ASSERT_OK(key->PublicKey(&pub));
    SG_PublicKey proof_pub;
    std::memcpy(proof_pub.bytes, pub.data(), pub.size());

    Server fake;
    fake.Start(EvilLeaf(), nullptr);  // attacker has no access to the real proof key
    ClientPtr client = NewClient();
    fake.Register(client.get());
    const std::string both = RealCa().cert_pem + EvilCa().cert_pem;

    SG_ServerConfig t = Target(fake.port, both);
    SG_ASSERT_OK(SG_Client_Connect(client.get(), &t));
    SG_EXPECT_OK(SG_Client_Authenticate(client.get()));  // limitation: fooled without a proof key
    SG_ASSERT_OK(SG_Client_Disconnect(client.get()));

    t.proof_keys = &proof_pub;
    t.proof_key_count = 1;
    SG_ASSERT_OK(SG_Client_Connect(client.get(), &t));
    SG_EXPECT_STATUS(SG_Client_Authenticate(client.get()), SG_INVALID_SIGNATURE);
}

SG_TEST(ProxyConfig, ParsingAndBypass)
{
    using sg::client::ResolvedProxy;
    ResolvedProxy p;
    SG_ASSERT_OK(sg::client::ParseProxyUrl("socks5h://bob:pw@proxy.corp:1081", &p));
    SG_EXPECT_EQ(p.type, SG_PROXY_TYPE_SOCKS5);
    SG_EXPECT_EQ(p.host, std::string("proxy.corp"));
    SG_EXPECT_EQ(p.port, static_cast<uint16_t>(1081));
    SG_EXPECT_EQ(p.username, std::string("bob"));
    SG_EXPECT(std::string(p.password.begin(), p.password.end()) == "pw");

    ResolvedProxy h;
    SG_ASSERT_OK(sg::client::ParseProxyUrl("http://10.0.0.1:3128/", &h));
    SG_EXPECT_EQ(h.type, SG_PROXY_TYPE_HTTP_CONNECT);
    SG_EXPECT_EQ(h.port, static_cast<uint16_t>(3128));
    ResolvedProxy bare;
    SG_ASSERT_OK(sg::client::ParseProxyUrl("proxy:8080", &bare));
    SG_EXPECT_EQ(bare.type, SG_PROXY_TYPE_HTTP_CONNECT);
    ResolvedProxy v6;
    SG_ASSERT_OK(sg::client::ParseProxyUrl("socks5://[::1]:1080", &v6));
    SG_EXPECT_EQ(v6.host, std::string("::1"));

    SG_EXPECT_STATUS(sg::client::ParseProxyUrl("https://proxy:443", &p), SG_NOT_SUPPORTED);
    SG_EXPECT_STATUS(sg::client::ParseProxyUrl("http://bad host:1", &p), SG_INVALID_ARGUMENT);
    SG_EXPECT_STATUS(sg::client::ParseProxyUrl("http://proxy:99999", &p), SG_INVALID_ARGUMENT);
    SG_EXPECT_STATUS(sg::client::ParseProxyUrl("http://proxy:0", &p), SG_INVALID_ARGUMENT);
    SG_EXPECT_STATUS(sg::client::ParseProxyUrl("http://pr\r\noxy:80", &p), SG_INVALID_ARGUMENT);

    ResolvedProxy w;
    SG_ASSERT_OK(sg::client::ParseWindowsProxyList("http=h1:80;https=h2:443;socks=h3:1080", &w));
    SG_EXPECT_EQ(w.host, std::string("h2"));
    SG_ASSERT_OK(sg::client::ParseWindowsProxyList("socks=h3:1080", &w));
    SG_EXPECT_EQ(w.type, SG_PROXY_TYPE_SOCKS4A);
    SG_ASSERT_OK(sg::client::ParseWindowsProxyList("single:8080", &w));
    SG_EXPECT_EQ(w.host, std::string("single"));
    SG_EXPECT_STATUS(sg::client::ParseWindowsProxyList("", &w), SG_NOT_FOUND);

    SG_EXPECT(sg::client::MatchesProxyBypass("intranet", "<local>"));
    SG_EXPECT(!sg::client::MatchesProxyBypass("gate.example.com", "<local>"));
    SG_EXPECT(sg::client::MatchesProxyBypass("a.example.com", "localhost,.example.com"));
    SG_EXPECT(sg::client::MatchesProxyBypass("example.com", ".example.com"));
    SG_EXPECT(sg::client::MatchesProxyBypass("a.example.com", "*.example.com"));
    SG_EXPECT(sg::client::MatchesProxyBypass("a.example.com", "example.com"));
    SG_EXPECT(!sg::client::MatchesProxyBypass("badexample.com", "example.com"));
    SG_EXPECT(sg::client::MatchesProxyBypass("anything", "*"));
    SG_EXPECT(!sg::client::MatchesProxyBypass("gate.example.com", ""));
}
