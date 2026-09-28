// Phase 4: authentication handshake and attacks against it. Frames are
// exchanged directly between the sans-IO handshake objects; channel binding
// values come from real (in-memory) TLS sessions so relay/MITM scenarios use
// genuinely different TLS connections.
#include "sg_test.h"

#include "auth/client_handshake.h"
#include "auth/server_handshake.h"
#include "crypto/key_store.h"
#include "storage/atomic_file.h"
#include "storage/client_registry.h"
#include "support/test_pki.h"

#include "sockgate_common/protocol/enrollment_token.h"
#include "sockgate_common/protocol/transcript.h"

#include "sockgate_common/core/clock.h"

#include <atomic>

#ifdef _WIN32
#include <windows.h>
#include <aclapi.h>
#endif
#include <filesystem>
#include <fstream>
#include <iterator>

using namespace sg;
using namespace sg::client;
using namespace sg::server;
using namespace sgtest;

namespace {

struct TlsSession {
    std::unique_ptr<tls::ITlsEngine> client;
    std::unique_ptr<tls::ITlsEngine> server;
    crypto::Sha256Digest client_cb{};
    crypto::Sha256Digest server_cb{};
};

const TestCert& Ca()
{
    static const TestCert ca = CreateRootCa("Handshake Test CA");
    return ca;
}
const TestCert& Leaf()
{
    static const TestCert leaf = IssueLocalhostServer(Ca());
    return leaf;
}

TlsSession NewTlsSession()
{
    std::shared_ptr<tls::ITlsContext> cctx, sctx;
    SG_ASSERT_OK(tls::DefaultTlsProvider().CreateClientContext(ClientConfigTrusting(Ca()), &cctx));
    SG_ASSERT_OK(tls::DefaultTlsProvider().CreateServerContext(ServerConfigFor(Leaf()), &sctx));
    TlsSession s;
    SG_ASSERT_OK(cctx->CreateEngine(&s.client));
    SG_ASSERT_OK(sctx->CreateEngine(&s.server));
    SG_ASSERT_OK(PumpHandshake(*s.client, *s.server));
    SG_ASSERT_OK(s.client->ChannelBinding(&s.client_cb));
    SG_ASSERT_OK(s.server->ChannelBinding(&s.server_cb));
    return s;
}

proto::DecodedFrame Decode(const Bytes& wire)
{
    proto::FrameDecoder d([](const proto::FrameHeader&) { return OkStatus(); });
    SG_ASSERT_OK(d.Append(wire));
    proto::DecodedFrame f;
    bool ready = false;
    SG_ASSERT_OK(d.Next(&f, &ready));
    SG_ASSERT(ready);
    return f;
}

struct ServerSide {
    std::unique_ptr<IClientRegistry> registry = CreateMemoryClientRegistry();
    AllowRegisteredAuthorizer allow_all;
    IAuthorizer* authorizer = &allow_all;
    std::shared_ptr<ServerAuthContext> ctx;
    std::atomic<uint64_t> mono{1'000'000};
    std::atomic<uint64_t> unix_now{1'700'000'000'000ull};

    void Init(HandshakeConfig cfg = HandshakeConfig())
    {
        cfg.monotonic_ms = [this]() { return mono.load(); };
        cfg.unix_ms = [this]() { return unix_now.load(); };
        SG_ASSERT_OK(ServerAuthContext::Create(std::move(cfg), registry.get(), authorizer, &ctx));
    }

    void Register(IKeyStore& ks, const std::string& name)
    {
        IdentityInfo id;
        SG_ASSERT_OK(EnsureIdentity(ks, name, &id));
        ClientRecord rec;
        rec.installation_id = id.installation_id;
        rec.public_key = id.public_key;
        SG_ASSERT_OK(registry->Register(rec));
    }
};

struct Outcome {
    Status client = SG_INTERNAL_ERROR;
    Status server = SG_INTERNAL_ERROR;
    ClientHandshakeResult client_result;
    HandshakeOutcome server_outcome;
    Bytes hello_frame;
    Bytes proof_frame;
};

// Runs one handshake. client_cb/server_cb may differ to model a MITM.
Outcome Run(ServerSide& server, IKeyStore& ks, const std::string& key, const crypto::Sha256Digest& client_cb,
            const crypto::Sha256Digest& server_cb, ClientHandshakeConfig ccfg = ClientHandshakeConfig(),
            const EnrollmentMaterial* enroll = nullptr, const std::function<void()>& before_proof = nullptr)
{
    Outcome o;
    ClientHandshake client(std::move(ccfg), ks, key);
    ServerHandshake srv(server.ctx);

    o.client = client.Start(client_cb, enroll, &o.hello_frame);
    if (!o.client.ok()) return o;
    Bytes server_hello;
    o.server = srv.OnClientHello(Decode(o.hello_frame), server_cb, "test-peer", &server_hello);
    if (o.server == SG_VERSION_MISMATCH) {
        o.client = client.OnAuthResult(Decode(server_hello), &o.client_result);
        return o;
    }
    if (!o.server.ok()) return o;
    o.client = client.OnServerHello(Decode(server_hello), &o.proof_frame);
    if (!o.client.ok()) return o;
    if (before_proof) before_proof();
    Bytes auth_result;
    o.server = srv.OnClientProof(Decode(o.proof_frame), &auth_result, &o.server_outcome);
    if (auth_result.empty()) {
        o.client = SG_CLOSED;
        return o;
    }
    o.client = client.OnAuthResult(Decode(auth_result), &o.client_result);
    return o;
}

Outcome RunSameSession(ServerSide& server, IKeyStore& ks, const std::string& key,
                       ClientHandshakeConfig ccfg = ClientHandshakeConfig(), const EnrollmentMaterial* enroll = nullptr,
                       const std::function<void()>& before_proof = nullptr)
{
    const TlsSession tls = NewTlsSession();
    return Run(server, ks, key, tls.client_cb, tls.server_cb, std::move(ccfg), enroll, before_proof);
}

EnrollmentMaterial MakeToken(ServerSide& server, const std::string& product = "prod", uint64_t ttl_ms = 3'600'000,
                             uint8_t token_byte = 1)
{
    proto::EnrollmentClaims claims;
    claims.token_id.fill(token_byte);
    claims.product_id = product;
    claims.license_id = "LIC-1";
    claims.issued_at_ms = server.unix_now.load();
    claims.expires_at_ms = claims.issued_at_ms + ttl_ms;
    std::string token;
    SG_ASSERT_OK(proto::BuildEnrollmentToken(server.ctx->config.token_key, claims, &token));
    EnrollmentMaterial m;
    SG_ASSERT_OK(proto::ParseEnrollmentToken(token, &m.token_pub, &m.k_tok));
    return m;
}

HandshakeConfig EnrollConfig()
{
    HandshakeConfig cfg;
    cfg.allow_enrollment = true;
    cfg.token_key.assign(32, 0x5A);
    return cfg;
}

}  // namespace

SG_TEST(Handshake, RegisteredClientAuthenticates)
{
    ServerSide server;
    server.Init();
    auto ks = CreateMemoryKeyStore();
    server.Register(*ks, "app");

    const Outcome o = RunSameSession(server, *ks, "app");
    SG_ASSERT_OK(o.server);
    SG_ASSERT_OK(o.client);
    SG_EXPECT(o.client_result.session_id == o.server_outcome.session_id);
    SG_EXPECT(o.client_result.transcript_hash == o.server_outcome.transcript_hash);
    SG_EXPECT(o.client_result.auth_result.policy == proto::SessionPolicy::kNormal);
    SG_EXPECT_EQ(o.client_result.auth_result.session_lifetime_ms, 3'600'000u);
    SG_EXPECT(!o.server_outcome.enrolled);
}

SG_TEST(Handshake, UnknownAndRevokedInstallationsRejected)
{
    ServerSide server;
    server.Init();
    auto ks = CreateMemoryKeyStore();
    IdentityInfo id;
    SG_ASSERT_OK(EnsureIdentity(*ks, "app", &id));

    Outcome o = RunSameSession(server, *ks, "app");
    SG_EXPECT_STATUS(o.server, SG_AUTH_FAILED);
    SG_EXPECT_STATUS(o.client, SG_SERVER_REJECTED);

    server.Register(*ks, "app");
    SG_ASSERT_OK(server.registry->Revoke(id.installation_id));
    o = RunSameSession(server, *ks, "app");
    SG_EXPECT_STATUS(o.server, SG_AUTH_FAILED);
    SG_EXPECT_STATUS(o.client, SG_SERVER_REJECTED);
}

SG_TEST(Handshake, ImpersonationWithForeignKeyRejected)
{
    // The attacker knows the victim's installation id but not its key: it
    // claims the victim's id and signs with its own key.
    ServerSide server;
    server.Init();
    auto victim = CreateMemoryKeyStore();
    server.Register(*victim, "victim");
    IdentityInfo victim_id;
    SG_ASSERT_OK(GetIdentity(*victim, "victim", &victim_id));

    auto attacker = CreateMemoryKeyStore();
    SG_ASSERT_OK(attacker->GenerateKeyPair("attacker"));

    const TlsSession tls = NewTlsSession();
    ClientHandshake client(ClientHandshakeConfig(), *attacker, "attacker");
    Bytes hello_frame;
    SG_ASSERT_OK(client.Start(tls.client_cb, nullptr, &hello_frame));
    // Rewrite the claimed installation id inside CLIENT_HELLO (offset: header + 5*u16 + nonce).
    const size_t iid_offset = proto::kHeaderSize + 10 + proto::kNonceSize;
    std::copy(victim_id.installation_id.begin(), victim_id.installation_id.end(),
              hello_frame.begin() + static_cast<std::ptrdiff_t>(iid_offset));

    ServerHandshake srv(server.ctx);
    Bytes server_hello;
    SG_ASSERT_OK(srv.OnClientHello(Decode(hello_frame), tls.server_cb, "attacker", &server_hello));
    // The client computes its transcript over the frame it sent originally, so
    // produce the proof with a handshake that saw the modified frame instead.
    const proto::DecodedFrame sh = Decode(server_hello);
    crypto::Sha256Digest th1;
    SG_ASSERT_OK(proto::ComputeTranscriptHash(1, tls.client_cb, hello_frame, sh.wire(), &th1));
    proto::ClientProof proof;
    SG_ASSERT_OK(attacker->Sign("attacker", proto::SignedData(proto::kClientProofContext, th1), &proof.signature));
    Bytes payload;
    SG_ASSERT_OK(proto::EncodeClientProof(proof, &payload));
    proto::FrameHeader h;
    h.type = proto::MessageType::kClientProof;
    h.session_id = sh.header().session_id;
    h.sequence = 2;
    Bytes proof_frame;
    SG_ASSERT_OK(proto::EncodeFrame(h, payload, ByteView(), &proof_frame));

    Bytes result;
    HandshakeOutcome outcome;
    SG_EXPECT_STATUS(srv.OnClientProof(Decode(proof_frame), &result, &outcome), SG_AUTH_FAILED);
    SG_EXPECT(srv.failure_reason() == "invalid signature");
}

SG_TEST(Handshake, TamperedSignatureRejected)
{
    ServerSide server;
    server.Init();
    auto ks = CreateMemoryKeyStore();
    server.Register(*ks, "app");
    const TlsSession tls = NewTlsSession();
    ClientHandshake client(ClientHandshakeConfig(), *ks, "app");
    ServerHandshake srv(server.ctx);
    Bytes hello, server_hello, proof, result;
    SG_ASSERT_OK(client.Start(tls.client_cb, nullptr, &hello));
    SG_ASSERT_OK(srv.OnClientHello(Decode(hello), tls.server_cb, "p", &server_hello));
    SG_ASSERT_OK(client.OnServerHello(Decode(server_hello), &proof));
    proof[proto::kHeaderSize + 3 + 10] ^= 0x01;  // inside the signature
    HandshakeOutcome outcome;
    SG_EXPECT_STATUS(srv.OnClientProof(Decode(proof), &result, &outcome), SG_AUTH_FAILED);
    ClientHandshakeResult cr;
    SG_EXPECT_STATUS(client.OnAuthResult(Decode(result), &cr), SG_SERVER_REJECTED);
}

SG_TEST(Handshake, ExpiredChallengeRejected)
{
    HandshakeConfig cfg;
    cfg.challenge_ttl_ms = 1000;
    ServerSide server;
    server.Init(cfg);
    auto ks = CreateMemoryKeyStore();
    server.Register(*ks, "app");
    const Outcome o = RunSameSession(server, *ks, "app", ClientHandshakeConfig(), nullptr,
                                     [&]() { server.mono += 1001; });
    SG_EXPECT_STATUS(o.server, SG_AUTH_FAILED);
    SG_EXPECT_STATUS(o.client, SG_SERVER_REJECTED);
}

SG_TEST(Handshake, ChallengeCannotBeReused)
{
    ServerSide server;
    server.Init();
    auto ks = CreateMemoryKeyStore();
    server.Register(*ks, "app");
    const TlsSession tls = NewTlsSession();
    ClientHandshake client(ClientHandshakeConfig(), *ks, "app");
    ServerHandshake srv(server.ctx);
    Bytes hello, server_hello, proof, result;
    SG_ASSERT_OK(client.Start(tls.client_cb, nullptr, &hello));
    SG_ASSERT_OK(srv.OnClientHello(Decode(hello), tls.server_cb, "p", &server_hello));
    SG_ASSERT_OK(client.OnServerHello(Decode(server_hello), &proof));
    HandshakeOutcome outcome;
    SG_ASSERT_OK(srv.OnClientProof(Decode(proof), &result, &outcome));
    // Same proof again on the same connection: the single attempt is spent.
    SG_EXPECT_STATUS(srv.OnClientProof(Decode(proof), &result, &outcome), SG_PROTOCOL_ERROR);
    // A second CLIENT_HELLO is not accepted either.
    SG_EXPECT_STATUS(srv.OnClientHello(Decode(hello), tls.server_cb, "p", &server_hello), SG_PROTOCOL_ERROR);
}

SG_TEST(Handshake, ReplayedAuthenticationOnNewConnectionRejected)
{
    ServerSide server;
    server.Init();
    auto ks = CreateMemoryKeyStore();
    server.Register(*ks, "app");
    const Outcome original = RunSameSession(server, *ks, "app");
    SG_ASSERT_OK(original.server);

    // An attacker replays the captured CLIENT_HELLO / CLIENT_PROOF on a new connection.
    const TlsSession tls = NewTlsSession();
    ServerHandshake srv(server.ctx);
    Bytes server_hello;
    SG_ASSERT_OK(srv.OnClientHello(Decode(original.hello_frame), tls.server_cb, "replayer", &server_hello));
    Bytes result;
    HandshakeOutcome outcome;
    // Session id differs, so the stale proof is not even well-formed here...
    SG_EXPECT_STATUS(srv.OnClientProof(Decode(original.proof_frame), &result, &outcome), SG_PROTOCOL_ERROR);

    // ...and with the session id patched in, the signature covers the old challenge and channel.
    ServerHandshake srv2(server.ctx);
    SG_ASSERT_OK(srv2.OnClientHello(Decode(original.hello_frame), tls.server_cb, "replayer", &server_hello));
    Bytes patched = original.proof_frame;
    const proto::SessionId sid = Decode(server_hello).header().session_id;
    std::copy(sid.begin(), sid.end(), patched.begin() + 8);
    SG_EXPECT_STATUS(srv2.OnClientProof(Decode(patched), &result, &outcome), SG_AUTH_FAILED);
    SG_EXPECT(srv2.failure_reason() == "invalid signature");
}

SG_TEST(Handshake, TlsTerminatingRelayRejected)
{
    // A MITM with a certificate the client trusts terminates TLS on both sides
    // and relays every SockGate frame unchanged. The client signs over its
    // channel binding; the server verifies against a different one.
    ServerSide server;
    server.Init();
    auto ks = CreateMemoryKeyStore();
    server.Register(*ks, "app");
    const TlsSession client_to_mitm = NewTlsSession();
    const TlsSession mitm_to_server = NewTlsSession();
    const Outcome o = Run(server, *ks, "app", client_to_mitm.client_cb, mitm_to_server.server_cb);
    SG_EXPECT_STATUS(o.server, SG_AUTH_FAILED);
    SG_EXPECT_STATUS(o.client, SG_SERVER_REJECTED);
}

SG_TEST(Handshake, VersionNegotiationFailure)
{
    ServerSide server;
    server.Init();
    auto ks = CreateMemoryKeyStore();
    server.Register(*ks, "app");
    ClientHandshakeConfig cfg;
    cfg.version_min = 2;
    cfg.version_max = 3;
    const Outcome o = RunSameSession(server, *ks, "app", cfg);
    SG_EXPECT_STATUS(o.server, SG_VERSION_MISMATCH);
    SG_EXPECT_STATUS(o.client, SG_VERSION_MISMATCH);
}

SG_TEST(Handshake, AuthorizationDenialAndLicenseCap)
{
    struct Policy final : IAuthorizer {
        bool allow = true;
        uint64_t license_expiry = 0;
        Status Authorize(const AuthorizationRequest& r, AuthorizationDecision* d) override
        {
            d->allow = allow && r.record != nullptr;
            d->granted_features = 0x3;
            d->license_expires_at_ms = license_expiry;
            if (!allow) d->deny_reason = "test policy";
            return OkStatus();
        }
    } policy;
    ServerSide server;
    server.authorizer = &policy;
    server.Init();
    auto ks = CreateMemoryKeyStore();
    server.Register(*ks, "app");

    policy.license_expiry = server.unix_now.load() + 5000;
    Outcome o = RunSameSession(server, *ks, "app");
    SG_ASSERT_OK(o.client);
    SG_EXPECT_EQ(o.client_result.auth_result.granted_features, uint64_t{3});
    SG_EXPECT_EQ(o.client_result.auth_result.session_lifetime_ms, 5000u);  // capped at license expiry

    policy.license_expiry = server.unix_now.load() - 1;
    o = RunSameSession(server, *ks, "app");
    SG_EXPECT_STATUS(o.client, SG_SERVER_REJECTED);

    policy.license_expiry = 0;
    policy.allow = false;
    o = RunSameSession(server, *ks, "app");
    SG_EXPECT_STATUS(o.server, SG_AUTH_FAILED);
    SG_EXPECT_STATUS(o.client, SG_SERVER_REJECTED);
}

SG_TEST(Handshake, ServerProofKeys)
{
    std::unique_ptr<crypto::SoftwareP256Key> proof_key;
    SG_ASSERT_OK(crypto::SoftwareP256Key::Generate(&proof_key));
    crypto::P256PublicKey proof_pub;
    SG_ASSERT_OK(proof_key->PublicKey(&proof_pub));
    std::unique_ptr<crypto::SoftwareP256Key> other_key;
    SG_ASSERT_OK(crypto::SoftwareP256Key::Generate(&other_key));
    crypto::P256PublicKey other_pub;
    SG_ASSERT_OK(other_key->PublicKey(&other_pub));

    auto ks = CreateMemoryKeyStore();
    {
        HandshakeConfig cfg;
        cfg.proof_key = std::shared_ptr<const crypto::SoftwareP256Key>(std::move(proof_key));
        ServerSide server;
        server.Init(cfg);
        server.Register(*ks, "app");

        ClientHandshakeConfig ccfg;
        ccfg.server_proof_keys = {other_pub, proof_pub};  // rotation: any configured key
        SG_EXPECT_OK(RunSameSession(server, *ks, "app", ccfg).client);

        ccfg.server_proof_keys = {other_pub};  // impostor key
        SG_EXPECT_STATUS(RunSameSession(server, *ks, "app", ccfg).client, SG_INVALID_SIGNATURE);
    }
    {
        // Server without a proof key while the client requires one: no downgrade.
        ServerSide server;
        server.Init();
        server.Register(*ks, "app2");
        ClientHandshakeConfig ccfg;
        ccfg.server_proof_keys = {proof_pub};
        SG_EXPECT_STATUS(RunSameSession(server, *ks, "app2", ccfg).client, SG_INVALID_SIGNATURE);
    }
}

SG_TEST(Enrollment, ValidTokenEnrollsAndAuthenticates)
{
    ServerSide server;
    server.Init(EnrollConfig());
    auto ks = CreateMemoryKeyStore();
    IdentityInfo id;
    SG_ASSERT_OK(EnsureIdentity(*ks, "app", &id));

    const EnrollmentMaterial token = MakeToken(server);
    ClientHandshakeConfig ccfg;
    ccfg.product_id = "prod";
    const Outcome o = RunSameSession(server, *ks, "app", ccfg, &token);
    SG_ASSERT_OK(o.server);
    SG_ASSERT_OK(o.client);
    SG_EXPECT(o.server_outcome.enrolled);
    ClientRecord rec;
    SG_ASSERT_OK(server.registry->Find(id.installation_id, &rec));
    SG_EXPECT_EQ(rec.product_id, std::string("prod"));
    SG_EXPECT_EQ(rec.license_id, std::string("LIC-1"));

    // Afterwards the installation authenticates normally.
    SG_EXPECT_OK(RunSameSession(server, *ks, "app").client);
}

SG_TEST(Enrollment, TokenIsSingleUse)
{
    ServerSide server;
    server.Init(EnrollConfig());
    const EnrollmentMaterial token = MakeToken(server);
    auto first = CreateMemoryKeyStore();
    SG_ASSERT_OK(first->GenerateKeyPair("a"));
    SG_ASSERT_OK(RunSameSession(server, *first, "a", ClientHandshakeConfig(), &token).client);

    auto second = CreateMemoryKeyStore();
    SG_ASSERT_OK(second->GenerateKeyPair("b"));
    const Outcome o = RunSameSession(server, *second, "b", ClientHandshakeConfig(), &token);
    SG_EXPECT_STATUS(o.client, SG_SERVER_REJECTED);
}

SG_TEST(Enrollment, ModifiedExpiredAndForgedTokensRejected)
{
    ServerSide server;
    server.Init(EnrollConfig());
    auto ks = CreateMemoryKeyStore();
    SG_ASSERT_OK(ks->GenerateKeyPair("app"));

    {   // Modified claims (extended expiry) with the original K_tok.
        EnrollmentMaterial token = MakeToken(server, "prod", 3'600'000, 2);
        token.token_pub[token.token_pub.size() - 2] ^= 0x10;
        SG_EXPECT_STATUS(RunSameSession(server, *ks, "app", ClientHandshakeConfig(), &token).client, SG_SERVER_REJECTED);
    }
    {   // Expired.
        const EnrollmentMaterial token = MakeToken(server, "prod", 1000, 3);
        server.unix_now += 1000;
        SG_EXPECT_STATUS(RunSameSession(server, *ks, "app", ClientHandshakeConfig(), &token).client, SG_SERVER_REJECTED);
    }
    {   // Attacker saw token_pub on the wire but does not know K_tok.
        EnrollmentMaterial token = MakeToken(server, "prod", 3'600'000, 4);
        SG_ASSERT_OK(crypto::RandomArray(&token.k_tok));
        SG_EXPECT_STATUS(RunSameSession(server, *ks, "app", ClientHandshakeConfig(), &token).client, SG_SERVER_REJECTED);
    }
    {   // Claims mismatch: token for another product.
        const EnrollmentMaterial token = MakeToken(server, "other-product", 3'600'000, 5);
        ClientHandshakeConfig ccfg;
        ccfg.product_id = "prod";
        SG_EXPECT_STATUS(RunSameSession(server, *ks, "app", ccfg, &token).client, SG_SERVER_REJECTED);
    }
    {   // Token issued by a different server secret.
        ServerSide other;
        HandshakeConfig cfg = EnrollConfig();
        cfg.token_key.assign(32, 0x77);
        other.Init(cfg);
        const EnrollmentMaterial token = MakeToken(other, "prod", 3'600'000, 6);
        SG_EXPECT_STATUS(RunSameSession(server, *ks, "app", ClientHandshakeConfig(), &token).client, SG_SERVER_REJECTED);
    }
    SG_EXPECT_EQ(server.registry->Count(), size_t{0});
}

SG_TEST(Enrollment, RelayedEnrollmentRejected)
{
    // A MITM (user-installed CA, no pinning) relays the victim's enrollment:
    // the enrollment proof is bound to the victim's TLS channel.
    ServerSide server;
    server.Init(EnrollConfig());
    auto ks = CreateMemoryKeyStore();
    SG_ASSERT_OK(ks->GenerateKeyPair("victim"));
    const EnrollmentMaterial token = MakeToken(server);
    const TlsSession a = NewTlsSession();
    const TlsSession b = NewTlsSession();
    const Outcome o = Run(server, *ks, "victim", a.client_cb, b.server_cb, ClientHandshakeConfig(), &token);
    SG_EXPECT_STATUS(o.client, SG_SERVER_REJECTED);
    // The token was not consumed by the failed attempt.
    SG_EXPECT_OK(RunSameSession(server, *ks, "victim", ClientHandshakeConfig(), &token).client);
}

SG_TEST(Enrollment, DisabledByDefault)
{
    ServerSide server;
    HandshakeConfig cfg = EnrollConfig();
    cfg.allow_enrollment = false;
    server.Init(cfg);
    auto ks = CreateMemoryKeyStore();
    SG_ASSERT_OK(ks->GenerateKeyPair("app"));
    const EnrollmentMaterial token = MakeToken(server);
    SG_EXPECT_STATUS(RunSameSession(server, *ks, "app", ClientHandshakeConfig(), &token).client, SG_SERVER_REJECTED);
}

SG_TEST(Enrollment, ExternalValidator)
{
    ServerSide server;
    HandshakeConfig cfg;
    cfg.allow_enrollment = true;
    const crypto::Sha256Digest external_k = []() {
        crypto::Sha256Digest k;
        k.fill(0x33);
        return k;
    }();
    cfg.enroll_validator = [&](const EnrollmentRequest& req, crypto::Sha256Digest* k) {
        if (req.token_pub != Bytes({'o', 'k'})) return Status(SG_AUTH_FAILED);
        *k = external_k;
        return OkStatus();
    };
    server.Init(cfg);
    auto ks = CreateMemoryKeyStore();
    SG_ASSERT_OK(ks->GenerateKeyPair("app"));
    EnrollmentMaterial m;
    m.token_pub = {'o', 'k'};
    m.k_tok = external_k;
    ClientHandshakeConfig claims;
    claims.product_id = "prod";
    claims.license_id = "PREMIUM";
    SG_EXPECT_OK(RunSameSession(server, *ks, "app", claims, &m).client);
    // The validator approved the token, not the license claim: no binding.
    IdentityInfo id;
    SG_ASSERT_OK(GetIdentity(*ks, "app", &id));
    ClientRecord rec;
    SG_ASSERT_OK(server.registry->Find(id.installation_id, &rec));
    SG_EXPECT_EQ(rec.product_id, std::string("prod"));
    SG_EXPECT(rec.license_id.empty());
    m.token_pub = {'n', 'o'};
    auto ks2 = CreateMemoryKeyStore();
    SG_ASSERT_OK(ks2->GenerateKeyPair("app"));
    SG_EXPECT_STATUS(RunSameSession(server, *ks2, "app", ClientHandshakeConfig(), &m).client, SG_SERVER_REJECTED);
}

SG_TEST(KeyStore, IdentityLifecycle)
{
    auto ks = CreateMemoryKeyStore();
    IdentityInfo a, b;
    SG_ASSERT_OK(EnsureIdentity(*ks, "com.example.app", &a));
    SG_EXPECT(a.created);
    SG_ASSERT_OK(EnsureIdentity(*ks, "com.example.app", &b));
    SG_EXPECT(!b.created);
    SG_EXPECT(a.installation_id == b.installation_id);
    SG_EXPECT_STATUS(ks->GenerateKeyPair("com.example.app"), SG_ALREADY_EXISTS);

    SG_EXPECT_STATUS(ValidateKeyName(""), SG_INVALID_ARGUMENT);
    SG_EXPECT_STATUS(ValidateKeyName("../escape"), SG_INVALID_ARGUMENT);
    SG_EXPECT_STATUS(ValidateKeyName("a/b"), SG_INVALID_ARGUMENT);
    SG_EXPECT_STATUS(ValidateKeyName(".."), SG_INVALID_ARGUMENT);
    SG_EXPECT_STATUS(ValidateKeyName(std::string(129, 'a')), SG_INVALID_ARGUMENT);
    SG_EXPECT_OK(ValidateKeyName("Product-1.2_x"));

    SG_ASSERT_OK(ks->DeleteKey("com.example.app"));
    SG_EXPECT_STATUS(GetIdentity(*ks, "com.example.app", &a), SG_NOT_FOUND);
    SG_EXPECT_STATUS(ks->DeleteKey("com.example.app"), SG_NOT_FOUND);
}

SG_TEST(Registry, RevocationSurvivesStorageFailure)
{
    namespace fs = std::filesystem;
    const fs::path dir = fs::temp_directory_path() / ("sockgate-registry-io-" + std::to_string(sg::MonotonicMs()));
    fs::create_directories(dir);
    auto ks = CreateMemoryKeyStore();
    IdentityInfo id;
    SG_ASSERT_OK(EnsureIdentity(*ks, "app", &id));
    std::unique_ptr<IClientRegistry> reg;
    SG_ASSERT_OK(CreateFileClientRegistry((dir / "registry.bin").string(), &reg));
    ClientRecord rec;
    rec.installation_id = id.installation_id;
    rec.public_key = id.public_key;
    SG_ASSERT_OK(reg->Register(rec));

    // Every further write fails: the store's path is now a directory.
    fs::remove(dir / "registry.bin");
    fs::create_directory(dir / "registry.bin");
    SG_EXPECT_STATUS(reg->Revoke(id.installation_id), SG_STORAGE_ERROR);
    ClientRecord after;
    SG_ASSERT_OK(reg->Find(id.installation_id, &after));
    SG_EXPECT(after.status == ClientStatus::kRevoked);
    SG_EXPECT_OK(reg->Revoke(id.installation_id));  // idempotent from now on
    reg.reset();
    fs::remove_all(dir);
}

SG_TEST(Registry, StoresAreLockedWhileOpen)
{
    namespace fs = std::filesystem;
    const fs::path dir = fs::temp_directory_path() / ("sockgate-lock-" + std::to_string(sg::MonotonicMs()));
    fs::create_directories(dir);
    const std::string path = (dir / "registry.bin").string();
    {
        std::unique_ptr<IClientRegistry> first;
        SG_ASSERT_OK(CreateFileClientRegistry(path, &first));
        // A second user of the same store (another process, e.g. sg_admin
        // while the server runs) would lose updates: refused.
        std::unique_ptr<IClientRegistry> second;
        SG_EXPECT_STATUS(CreateFileClientRegistry(path, &second), SG_INVALID_STATE);
    }
    std::unique_ptr<IClientRegistry> after;
    SG_EXPECT_OK(CreateFileClientRegistry(path, &after));  // released with the first store
    after.reset();
    fs::remove_all(dir);
}

SG_TEST(Registry, FilePersistenceAndCorruption)
{
    namespace fs = std::filesystem;
    const fs::path dir = fs::temp_directory_path() / ("sockgate-registry-" + std::to_string(sg::MonotonicMs()));
    fs::create_directories(dir);
    const std::string path = (dir / "registry.bin").string();

    auto ks = CreateMemoryKeyStore();
    IdentityInfo id;
    SG_ASSERT_OK(EnsureIdentity(*ks, "app", &id));
    {
        std::unique_ptr<IClientRegistry> reg;
        SG_ASSERT_OK(CreateFileClientRegistry(path, &reg));
        ClientRecord rec;
        rec.installation_id = id.installation_id;
        rec.public_key = id.public_key;
        rec.product_id = "prod";
        SG_ASSERT_OK(reg->Register(rec));
        proto::TokenId t{};
        t.fill(9);
        IdentityInfo id2;
        SG_ASSERT_OK(EnsureIdentity(*ks, "app2", &id2));
        ClientRecord rec2;
        rec2.installation_id = id2.installation_id;
        rec2.public_key = id2.public_key;
        SG_ASSERT_OK(reg->EnrollAtomically(rec2, t, 123));
        SG_EXPECT_STATUS(reg->EnrollAtomically(rec2, t, 123), SG_ALREADY_EXISTS);
        SG_ASSERT_OK(reg->Revoke(id2.installation_id));

        // Records whose id is not derived from the key are refused.
        ClientRecord bad = rec;
        bad.installation_id[0] ^= 1;
        SG_EXPECT_STATUS(reg->Register(bad), SG_INVALID_ARGUMENT);
    }
    {
        std::unique_ptr<IClientRegistry> reg;
        SG_ASSERT_OK(CreateFileClientRegistry(path, &reg));
        SG_EXPECT_EQ(reg->Count(), size_t{2});
        ClientRecord rec;
        SG_ASSERT_OK(reg->Find(id.installation_id, &rec));
        SG_EXPECT_EQ(rec.product_id, std::string("prod"));
        proto::TokenId t{};
        t.fill(9);
        SG_EXPECT(reg->IsTokenUsed(t));
    }
    {
        // Corrupt one byte of a stored public key: loading must fail closed.
        Bytes data;
        {
            std::ifstream f(path, std::ios::binary);
            data.assign(std::istreambuf_iterator<char>(f), std::istreambuf_iterator<char>());
        }
        data[10 + 16 + 30] ^= 0xFF;
        {
            std::ofstream f(path, std::ios::binary | std::ios::trunc);
            f.write(reinterpret_cast<const char*>(data.data()), static_cast<std::streamsize>(data.size()));
        }
        std::unique_ptr<IClientRegistry> reg;
        SG_EXPECT_STATUS(CreateFileClientRegistry(path, &reg), SG_STORAGE_ERROR);
    }
    fs::remove_all(dir);
}

#ifdef _WIN32
SG_TEST(Registry, StorageFilesAreOwnerOnly)
{
    namespace fs = std::filesystem;
    const fs::path dir = fs::temp_directory_path() / ("sockgate-acl-" + std::to_string(sg::MonotonicMs()));
    fs::create_directories(dir);
    const std::string path = (dir / "store.bin").string();
    const uint8_t data[] = {1, 2, 3};
    SG_ASSERT_OK(WriteFileAtomically(path, ByteView(data, sizeof(data))));

    PSECURITY_DESCRIPTOR sd = nullptr;
    PACL dacl = nullptr;
    SG_ASSERT(GetNamedSecurityInfoA(path.c_str(), SE_FILE_OBJECT, DACL_SECURITY_INFORMATION, nullptr, nullptr, &dacl,
                                    nullptr, &sd) == ERROR_SUCCESS);
    SECURITY_DESCRIPTOR_CONTROL control = 0;
    DWORD revision = 0;
    SG_EXPECT(GetSecurityDescriptorControl(sd, &control, &revision));
    SG_EXPECT((control & SE_DACL_PROTECTED) != 0);  // nothing inherited from the directory
    SG_ASSERT(dacl != nullptr);
    SG_EXPECT_EQ(dacl->AceCount, WORD{3});  // user, SYSTEM, Administrators
    for (DWORD i = 0; i < dacl->AceCount; ++i) {
        void* ace = nullptr;
        SG_ASSERT(GetAce(dacl, i, &ace));
        PSID sid = &static_cast<ACCESS_ALLOWED_ACE*>(ace)->SidStart;
        SG_EXPECT(!IsWellKnownSid(sid, WinBuiltinUsersSid) && !IsWellKnownSid(sid, WinWorldSid) &&
                  !IsWellKnownSid(sid, WinAuthenticatedUserSid));
    }
    LocalFree(sd);
    fs::remove_all(dir);
}
#endif
