// Phase 2: TLS engine tests (in memory, no sockets).
#include "sg_test.h"

#include "support/test_pki.h"

#include <openssl/pem.h>
#include <openssl/ssl.h>

#include <cstring>

using namespace sg;
using namespace sgtest;

namespace {

struct Pair {
    std::unique_ptr<tls::ITlsEngine> client;
    std::unique_ptr<tls::ITlsEngine> server;
};

Pair MakePair(const tls::TlsClientConfig& cc, const tls::TlsServerConfig& sc)
{
    std::shared_ptr<tls::ITlsContext> cctx, sctx;
    SG_ASSERT_OK(tls::DefaultTlsProvider().CreateClientContext(cc, &cctx));
    SG_ASSERT_OK(tls::DefaultTlsProvider().CreateServerContext(sc, &sctx));
    Pair p;
    SG_ASSERT_OK(cctx->CreateEngine(&p.client));
    SG_ASSERT_OK(sctx->CreateEngine(&p.server));
    return p;
}

std::string ReadAll(tls::ITlsEngine& e)
{
    std::string out;
    uint8_t buf[256];
    for (;;) {
        size_t n = 0;
        const Status st = e.Read(buf, sizeof(buf), &n);
        if (!st.ok()) break;
        out.append(reinterpret_cast<const char*>(buf), n);
    }
    return out;
}

ByteView Str(const std::string& s) { return ByteView(reinterpret_cast<const uint8_t*>(s.data()), s.size()); }

}  // namespace

SG_TEST(Tls, HandshakeAndDataRoundTrip)
{
    const TestCert ca = CreateRootCa("SockGate Test CA");
    const TestCert leaf = IssueLocalhostServer(ca);
    Pair p = MakePair(ClientConfigTrusting(ca), ServerConfigFor(leaf));

    Status server_status;
    SG_ASSERT_OK(PumpHandshake(*p.client, *p.server, &server_status));
    SG_ASSERT_OK(server_status);
    SG_EXPECT(p.client->IsHandshakeComplete());

    const tls::TlsSessionInfo info = p.client->SessionInfo();
    SG_EXPECT(info.tls13);
    SG_EXPECT_EQ(info.protocol, std::string("TLSv1.3"));

    // Channel binding and exporters agree on both ends of the same session.
    crypto::Sha256Digest cb_client, cb_server;
    SG_ASSERT_OK(p.client->ChannelBinding(&cb_client));
    SG_ASSERT_OK(p.server->ChannelBinding(&cb_server));
    SG_EXPECT(cb_client == cb_server);
    uint8_t k1[32], k2[32];
    SG_ASSERT_OK(p.client->ExportKeyingMaterial("EXPORTER-SockGate-v1-keys", Str("ctx"), true, k1, sizeof(k1)));
    SG_ASSERT_OK(p.server->ExportKeyingMaterial("EXPORTER-SockGate-v1-keys", Str("ctx"), true, k2, sizeof(k2)));
    SG_EXPECT(std::memcmp(k1, k2, sizeof(k1)) == 0);
    uint8_t k3[32];
    SG_ASSERT_OK(p.server->ExportKeyingMaterial("EXPORTER-SockGate-v1-keys", Str("ctX"), true, k3, sizeof(k3)));
    SG_EXPECT(std::memcmp(k1, k3, sizeof(k1)) != 0);

    SG_ASSERT_OK(p.client->Write(Str("ping")));
    SG_ASSERT_OK(Transfer(*p.client, *p.server));
    SG_EXPECT_EQ(ReadAll(*p.server), std::string("ping"));
    SG_ASSERT_OK(p.server->Write(Str("pong")));
    SG_ASSERT_OK(Transfer(*p.server, *p.client));
    SG_EXPECT_EQ(ReadAll(*p.client), std::string("pong"));
}

SG_TEST(Tls, ChannelBindingDiffersBetweenSessions)
{
    // Models a MITM terminating two separate TLS sessions: the values differ,
    // which is what makes relaying a client signature useless.
    const TestCert ca = CreateRootCa("CA");
    const TestCert leaf = IssueLocalhostServer(ca);
    Pair a = MakePair(ClientConfigTrusting(ca), ServerConfigFor(leaf));
    Pair b = MakePair(ClientConfigTrusting(ca), ServerConfigFor(leaf));
    SG_ASSERT_OK(PumpHandshake(*a.client, *a.server));
    SG_ASSERT_OK(PumpHandshake(*b.client, *b.server));
    crypto::Sha256Digest ca_cb, cb_cb;
    SG_ASSERT_OK(a.client->ChannelBinding(&ca_cb));
    SG_ASSERT_OK(b.server->ChannelBinding(&cb_cb));
    SG_EXPECT(ca_cb != cb_cb);
}

SG_TEST(Tls, UntrustedCaRejected)
{
    const TestCert trusted = CreateRootCa("Trusted CA");
    const TestCert attacker = CreateRootCa("Attacker CA");
    const TestCert leaf = IssueLocalhostServer(attacker);
    Pair p = MakePair(ClientConfigTrusting(trusted), ServerConfigFor(leaf));
    SG_EXPECT_STATUS(PumpHandshake(*p.client, *p.server), SG_CERTIFICATE_ERROR);
    SG_EXPECT(p.client->ErrorDetail().find("certificate") != std::string::npos);
    // A failed engine stays failed.
    SG_EXPECT_STATUS(p.client->Write(Str("x")), SG_CERTIFICATE_ERROR);
}

SG_TEST(Tls, HostnameMismatchRejected)
{
    const TestCert ca = CreateRootCa("CA");
    CertOptions o;
    o.dns_names = {"other.example"};
    const TestCert leaf = IssueCert(ca, "other.example", o);
    Pair p = MakePair(ClientConfigTrusting(ca, "gate.example"), ServerConfigFor(leaf));
    SG_EXPECT_STATUS(PumpHandshake(*p.client, *p.server), SG_CERTIFICATE_ERROR);
}

SG_TEST(Tls, PartialWildcardRejected)
{
    const TestCert ca = CreateRootCa("CA");
    CertOptions o;
    o.dns_names = {"ga*.example"};
    const TestCert leaf = IssueCert(ca, "wild", o);
    Pair p = MakePair(ClientConfigTrusting(ca, "gate.example"), ServerConfigFor(leaf));
    SG_EXPECT_STATUS(PumpHandshake(*p.client, *p.server), SG_CERTIFICATE_ERROR);
}

SG_TEST(Tls, IpAddressSanVerified)
{
    const TestCert ca = CreateRootCa("CA");
    const TestCert leaf = IssueLocalhostServer(ca);
    {
        Pair p = MakePair(ClientConfigTrusting(ca, "127.0.0.1"), ServerConfigFor(leaf));
        SG_EXPECT_OK(PumpHandshake(*p.client, *p.server));
    }
    {
        Pair p = MakePair(ClientConfigTrusting(ca, "127.0.0.2"), ServerConfigFor(leaf));
        SG_EXPECT_STATUS(PumpHandshake(*p.client, *p.server), SG_CERTIFICATE_ERROR);
    }
}

SG_TEST(Tls, ExpiredAndNotYetValidRejected)
{
    const TestCert ca = CreateRootCa("CA");
    CertOptions expired;
    expired.dns_names = {"localhost"};
    expired.not_before_offset_s = -10 * 24 * 3600;
    expired.not_after_offset_s = -24 * 3600;
    Pair p1 = MakePair(ClientConfigTrusting(ca), ServerConfigFor(IssueCert(ca, "localhost", expired)));
    SG_EXPECT_STATUS(PumpHandshake(*p1.client, *p1.server), SG_CERTIFICATE_ERROR);

    CertOptions future;
    future.dns_names = {"localhost"};
    future.not_before_offset_s = 24 * 3600;
    future.not_after_offset_s = 10 * 24 * 3600;
    Pair p2 = MakePair(ClientConfigTrusting(ca), ServerConfigFor(IssueCert(ca, "localhost", future)));
    SG_EXPECT_STATUS(PumpHandshake(*p2.client, *p2.server), SG_CERTIFICATE_ERROR);
}

SG_TEST(Tls, CaCertificateCannotActAsLeafSigner)
{
    // A leaf certificate (CA:FALSE) must not be accepted as an issuer.
    const TestCert ca = CreateRootCa("CA");
    const TestCert leaf = IssueLocalhostServer(ca);
    CertOptions o;
    o.dns_names = {"localhost"};
    const TestCert grandchild = IssueCert(leaf, "localhost", o);
    Pair p = MakePair(ClientConfigTrusting(ca), ServerConfigFor(grandchild, leaf.cert_pem));
    SG_EXPECT_STATUS(PumpHandshake(*p.client, *p.server), SG_CERTIFICATE_ERROR);
}

SG_TEST(Tls, OutdatedOpenSslIsReported)
{
    SG_EXPECT(tls::IsOutdatedOpenSsl(0x1010117FUL));   // 1.1.1w
    SG_EXPECT(tls::IsOutdatedOpenSsl(0x30000020UL));   // 3.0.2
    SG_EXPECT(tls::IsOutdatedOpenSsl(0x30000060UL));   // 3.0.6
    SG_EXPECT(!tls::IsOutdatedOpenSsl(0x30000070UL));  // 3.0.7
    SG_EXPECT(!tls::IsOutdatedOpenSsl(0x30100000UL));  // 3.1.0
    SG_EXPECT(!tls::IsOutdatedOpenSsl(0x30500040UL));  // 3.5.4
    // Only a bundled, outdated OpenSSL is reported, with its version string.
    const char* version = tls::OutdatedBundledOpenSslVersion();
    if (version != nullptr) {
        SG_EXPECT(tls::IsOutdatedOpenSsl(OpenSSL_version_num()));
        SG_EXPECT(std::strstr(version, "OpenSSL") != nullptr);
    }
#ifdef _WIN32
    // Windows builds always ship their OpenSSL.
    SG_EXPECT((version != nullptr) == tls::IsOutdatedOpenSsl(OpenSSL_version_num()));
#endif
}

SG_TEST(Tls, SpkiPinning)
{
    const TestCert ca = CreateRootCa("CA");
    const TestCert leaf = IssueLocalhostServer(ca);
    const TestCert unrelated = CreateRootCa("Unrelated");

    auto run = [&](std::vector<crypto::Sha256Digest> pins) {
        tls::TlsClientConfig cc = ClientConfigTrusting(ca);
        cc.spki_pins = std::move(pins);
        Pair p = MakePair(cc, ServerConfigFor(leaf));
        return PumpHandshake(*p.client, *p.server);
    };
    SG_EXPECT_OK(run({leaf.spki_sha256}));                           // leaf pin
    SG_EXPECT_OK(run({ca.spki_sha256}));                             // CA pin
    SG_EXPECT_OK(run({unrelated.spki_sha256, leaf.spki_sha256}));   // rotation: multiple pins
    SG_EXPECT_STATUS(run({unrelated.spki_sha256}), SG_PINNING_ERROR);
}

SG_TEST(Tls, PinningNotBypassedByAppendedGenuineCertificate)
{
    // CVE-2016-2402 pattern: the attacker controls a CA the client trusts
    // (user-installed) and appends the genuine pinned certificate to its
    // forged chain. Pins must only be matched against the verified chain.
    const TestCert genuine_ca = CreateRootCa("Genuine CA");
    const TestCert genuine_leaf = IssueLocalhostServer(genuine_ca);
    const TestCert attacker_ca = CreateRootCa("User-installed MITM CA");
    const TestCert forged_leaf = IssueLocalhostServer(attacker_ca);

    tls::TlsClientConfig cc;
    cc.server_name = "localhost";
    cc.ca_pem = genuine_ca.cert_pem + attacker_ca.cert_pem;  // attacker CA is trusted
    cc.spki_pins = {genuine_leaf.spki_sha256, genuine_ca.spki_sha256};

    Pair p = MakePair(cc, ServerConfigFor(forged_leaf, genuine_leaf.cert_pem + genuine_ca.cert_pem));
    SG_EXPECT_STATUS(PumpHandshake(*p.client, *p.server), SG_PINNING_ERROR);
}

SG_TEST(Tls, ServerContextValidation)
{
    const TestCert ca = CreateRootCa("CA");
    const TestCert leaf = IssueLocalhostServer(ca);
    const TestCert other = IssueLocalhostServer(ca);
    std::shared_ptr<tls::ITlsContext> ctx;

    tls::TlsServerConfig mismatched = ServerConfigFor(leaf);
    mismatched.private_key_pem.assign(other.key_pem.begin(), other.key_pem.end());
    SG_EXPECT_STATUS(tls::DefaultTlsProvider().CreateServerContext(mismatched, &ctx), SG_INVALID_ARGUMENT);

    tls::TlsServerConfig no_key = ServerConfigFor(leaf);
    no_key.private_key_pem.clear();
    SG_EXPECT_STATUS(tls::DefaultTlsProvider().CreateServerContext(no_key, &ctx), SG_INVALID_ARGUMENT);

    tls::TlsServerConfig garbage;
    garbage.cert_chain_pem = "not a certificate";
    garbage.private_key_pem.assign(leaf.key_pem.begin(), leaf.key_pem.end());
    SG_EXPECT_STATUS(tls::DefaultTlsProvider().CreateServerContext(garbage, &ctx), SG_CERTIFICATE_ERROR);
}

SG_TEST(Tls, ClientContextValidation)
{
    std::shared_ptr<tls::ITlsContext> ctx;
    tls::TlsClientConfig no_trust;
    no_trust.server_name = "localhost";
    SG_EXPECT_STATUS(tls::DefaultTlsProvider().CreateClientContext(no_trust, &ctx), SG_INVALID_ARGUMENT);

    tls::TlsClientConfig no_name;
    no_name.ca_pem = CreateRootCa("CA").cert_pem;
    SG_EXPECT_STATUS(tls::DefaultTlsProvider().CreateClientContext(no_name, &ctx), SG_INVALID_ARGUMENT);

    tls::TlsClientConfig bad_pem;
    bad_pem.server_name = "localhost";
    bad_pem.ca_pem = "garbage";
    SG_EXPECT_STATUS(tls::DefaultTlsProvider().CreateClientContext(bad_pem, &ctx), SG_CERTIFICATE_ERROR);

    tls::TlsClientConfig missing_file;
    missing_file.server_name = "localhost";
    missing_file.ca_file = "definitely-missing-ca-file.pem";
    SG_EXPECT_STATUS(tls::DefaultTlsProvider().CreateClientContext(missing_file, &ctx), SG_CERTIFICATE_ERROR);
}

SG_TEST(Tls, GarbageInputFailsServer)
{
    const TestCert ca = CreateRootCa("CA");
    Pair p = MakePair(ClientConfigTrusting(ca), ServerConfigFor(IssueLocalhostServer(ca)));
    const std::string junk = "GET / HTTP/1.1\r\nHost: x\r\n\r\n";
    SG_ASSERT_OK(p.server->FeedIncoming(Str(junk)));
    SG_EXPECT_STATUS(p.server->Handshake(), SG_TLS_ERROR);
}

SG_TEST(Tls, CloseNotifyAndKeyUpdate)
{
    const TestCert ca = CreateRootCa("CA");
    Pair p = MakePair(ClientConfigTrusting(ca), ServerConfigFor(IssueLocalhostServer(ca)));
    SG_ASSERT_OK(PumpHandshake(*p.client, *p.server));

    // KeyUpdate: traffic continues to flow in both directions afterwards.
    SG_ASSERT_OK(p.client->RequestKeyUpdate());
    SG_ASSERT_OK(p.client->Write(Str("after-update")));
    SG_ASSERT_OK(Transfer(*p.client, *p.server));
    SG_EXPECT_EQ(ReadAll(*p.server), std::string("after-update"));
    SG_ASSERT_OK(Transfer(*p.server, *p.client));  // server's KeyUpdate response
    SG_ASSERT_OK(p.server->Write(Str("reply")));
    SG_ASSERT_OK(Transfer(*p.server, *p.client));
    SG_EXPECT_EQ(ReadAll(*p.client), std::string("reply"));

    SG_ASSERT_OK(p.server->Shutdown());
    SG_ASSERT_OK(Transfer(*p.server, *p.client));
    uint8_t buf[8];
    size_t n = 0;
    SG_EXPECT_STATUS(p.client->Read(buf, sizeof(buf), &n), SG_CLOSED);
}

SG_TEST(Tls, TamperedRecordIsFatal)
{
    const TestCert ca = CreateRootCa("CA");
    Pair p = MakePair(ClientConfigTrusting(ca), ServerConfigFor(IssueLocalhostServer(ca)));
    SG_ASSERT_OK(PumpHandshake(*p.client, *p.server));
    SG_ASSERT_OK(p.client->Write(Str("secret payload")));
    Bytes wire;
    p.client->TakeOutgoing(&wire);
    SG_ASSERT(wire.size() > 10);
    wire[wire.size() - 5] ^= 0x01;
    SG_ASSERT_OK(p.server->FeedIncoming(wire));
    uint8_t buf[64];
    size_t n = 0;
    SG_EXPECT_STATUS(p.server->Read(buf, sizeof(buf), &n), SG_TLS_ERROR);
}

// ---- TLS 1.2 policy (uses a raw OpenSSL peer restricted to TLS 1.2) ---------

namespace {

struct RawTls12Server {
    SSL_CTX* ctx = nullptr;
    SSL* ssl = nullptr;
    BIO* rbio = nullptr;
    BIO* wbio = nullptr;

    RawTls12Server(const TestCert& leaf, bool disable_ems)
    {
        ctx = SSL_CTX_new(TLS_server_method());
        SSL_CTX_set_min_proto_version(ctx, TLS1_2_VERSION);
        SSL_CTX_set_max_proto_version(ctx, TLS1_2_VERSION);
        if (disable_ems) SSL_CTX_set_options(ctx, SSL_OP_NO_EXTENDED_MASTER_SECRET);
        SSL_CTX_use_certificate(ctx, static_cast<X509*>(leaf.cert.get()));
        SSL_CTX_use_PrivateKey(ctx, static_cast<EVP_PKEY*>(leaf.key.get()));
        ssl = SSL_new(ctx);
        rbio = BIO_new(BIO_s_mem());
        wbio = BIO_new(BIO_s_mem());
        BIO_set_mem_eof_return(rbio, -1);
        SSL_set_bio(ssl, rbio, wbio);
        SSL_set_accept_state(ssl);
    }
    ~RawTls12Server()
    {
        SSL_free(ssl);
        SSL_CTX_free(ctx);
    }

    // Returns the client's handshake status after pumping.
    Status Pump(tls::ITlsEngine& client)
    {
        Status cs = kStatusWouldBlock;
        for (int i = 0; i < 16 && cs == kStatusWouldBlock; ++i) {
            cs = client.Handshake();
            Bytes out;
            client.TakeOutgoing(&out);
            if (!out.empty()) BIO_write(rbio, out.data(), static_cast<int>(out.size()));
            SSL_do_handshake(ssl);
            char buf[16384];
            int n;
            while ((n = BIO_read(wbio, buf, sizeof(buf))) > 0) {
                if (!client.FeedIncoming(ByteView(reinterpret_cast<uint8_t*>(buf), static_cast<size_t>(n))).ok()) break;
            }
        }
        return cs;
    }
};

}  // namespace

SG_TEST(Tls, Tls12RejectedByDefault)
{
    const TestCert ca = CreateRootCa("CA");
    const TestCert leaf = IssueLocalhostServer(ca);
    RawTls12Server server(leaf, false);
    std::shared_ptr<tls::ITlsContext> cctx;
    SG_ASSERT_OK(tls::DefaultTlsProvider().CreateClientContext(ClientConfigTrusting(ca), &cctx));
    std::unique_ptr<tls::ITlsEngine> client;
    SG_ASSERT_OK(cctx->CreateEngine(&client));
    SG_EXPECT_STATUS(server.Pump(*client), SG_TLS_ERROR);
}

SG_TEST(Tls, Tls12AllowedOnlyWithExtendedMasterSecret)
{
    const TestCert ca = CreateRootCa("CA");
    const TestCert leaf = IssueLocalhostServer(ca);
    tls::TlsClientConfig cc = ClientConfigTrusting(ca);
    cc.allow_tls12 = true;
    std::shared_ptr<tls::ITlsContext> cctx;
    SG_ASSERT_OK(tls::DefaultTlsProvider().CreateClientContext(cc, &cctx));

    {
        RawTls12Server server(leaf, /*disable_ems=*/false);
        std::unique_ptr<tls::ITlsEngine> client;
        SG_ASSERT_OK(cctx->CreateEngine(&client));
        SG_EXPECT_OK(server.Pump(*client));
        const tls::TlsSessionInfo info = client->SessionInfo();
        SG_EXPECT(!info.tls13);
        SG_EXPECT(info.extended_master_secret);
    }
    {
        RawTls12Server server(leaf, /*disable_ems=*/true);
        std::unique_ptr<tls::ITlsEngine> client;
        SG_ASSERT_OK(cctx->CreateEngine(&client));
        SG_EXPECT_STATUS(server.Pump(*client), SG_TLS_ERROR);
        SG_EXPECT(client->ErrorDetail().find("extended master secret") != std::string::npos);
    }
}

SG_TEST(Tls, SpkiPinHelper)
{
    const TestCert ca = CreateRootCa("CA");
    crypto::Sha256Digest pin;
    SG_ASSERT_OK(tls::ComputeSpkiPinFromPem(Str(ca.cert_pem), &pin));
    SG_EXPECT(pin == ca.spki_sha256);
    SG_EXPECT_STATUS(tls::ComputeSpkiPinFromPem(Str("garbage"), &pin), SG_CERTIFICATE_ERROR);
}
