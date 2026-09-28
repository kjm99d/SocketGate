#include "sg_test.h"

#include "sockgate_common/protocol/enrollment_token.h"
#include "sockgate_common/protocol/messages.h"
#include "sockgate_common/protocol/rules.h"
#include "sockgate_common/protocol/transcript.h"
#include "sockgate_common/serialization/writer.h"

#include <cstring>
#include <functional>

using namespace sg;
using namespace sg::proto;

namespace {

ClientHello SampleHello()
{
    ClientHello h;
    h.client_version_major = 1;
    h.client_version_minor = 2;
    h.client_version_patch = 3;
    h.client_nonce.fill(0x11);
    h.installation_id.fill(0x22);
    h.product_id = "example-product";
    h.product_version = "1.2.3";
    h.license_id = "LIC-0001";
    h.has_requested_features = true;
    h.requested_features = 0x5;
    h.has_integrity = true;
    h.integrity.platform = 1;
    h.integrity.observation_flags = 0x3;
    h.integrity.executable_sha256.fill(0xAA);
    h.integrity.build_id = {1, 2, 3};
    return h;
}

// Every strict prefix of a valid encoding must be rejected (truncation), and
// so must the encoding with one trailing byte appended.
template <class T>
void ExpectTruncationAndTrailingRejected(const Bytes& valid, Status (*decode)(ByteView, T*), const char* name)
{
    for (size_t len = 0; len < valid.size(); ++len) {
        T out;
        if (decode(ByteView(valid.data(), len), &out).ok()) {
            sgtest::ReportFailure(__FILE__, __LINE__, std::string(name) + " accepted a truncated payload");
            return;
        }
    }
    Bytes trailing = valid;
    trailing.push_back(0);
    T out;
    if (decode(trailing, &out).ok()) {
        sgtest::ReportFailure(__FILE__, __LINE__, std::string(name) + " accepted trailing data");
    }
}

}  // namespace

SG_TEST(Messages, ClientHelloRoundTrip)
{
    const ClientHello in = SampleHello();
    Bytes wire;
    SG_ASSERT_OK(EncodeClientHello(in, &wire));
    SG_EXPECT(wire.size() <= kMaxHandshakePayload);
    ClientHello out;
    SG_ASSERT_OK(DecodeClientHello(wire, &out));
    SG_EXPECT(out.client_nonce == in.client_nonce);
    SG_EXPECT(out.installation_id == in.installation_id);
    SG_EXPECT_EQ(out.product_id, in.product_id);
    SG_EXPECT_EQ(out.product_version, in.product_version);
    SG_EXPECT_EQ(out.license_id, in.license_id);
    SG_EXPECT(out.has_requested_features && out.requested_features == 0x5);
    SG_EXPECT(out.has_integrity && out.integrity.build_id == in.integrity.build_id);
    SG_EXPECT(out.auth_mode == AuthMode::kAuthenticate);
    ExpectTruncationAndTrailingRejected<ClientHello>(wire, &DecodeClientHello, "ClientHello");
}

SG_TEST(Messages, ClientHelloFieldValidation)
{
    auto encode_raw = [](const std::function<void(ser::Writer&)>& fixed, const std::function<void(ser::TlvWriter&)>& ext) {
        Bytes out;
        ser::Writer w(&out);
        fixed(w);
        ser::TlvWriter t;
        ext(t);
        (void)t.Finish(w);
        return out;
    };
    auto fixed = [](uint16_t vmin, uint16_t vmax, uint8_t alg, uint8_t mode) {
        return [=](ser::Writer& w) {
            w.U16(vmin);
            w.U16(vmax);
            w.U16(1);
            w.U16(0);
            w.U16(0);
            w.Raw(Bytes(kNonceSize, 1));
            w.Raw(Bytes(kInstallationIdSize, 2));
            w.U8(alg);
            w.U8(mode);
        };
    };
    auto none = [](ser::TlvWriter&) {};
    ClientHello out;
    SG_EXPECT_OK(DecodeClientHello(encode_raw(fixed(1, 1, 1, 1), none), &out));
    SG_EXPECT_STATUS(DecodeClientHello(encode_raw(fixed(2, 1, 1, 1), none), &out), SG_PROTOCOL_ERROR);  // min > max
    SG_EXPECT_STATUS(DecodeClientHello(encode_raw(fixed(0, 1, 1, 1), none), &out), SG_PROTOCOL_ERROR);  // min 0
    SG_EXPECT_STATUS(DecodeClientHello(encode_raw(fixed(1, 1, 9, 1), none), &out), SG_PROTOCOL_ERROR);  // key alg
    SG_EXPECT_STATUS(DecodeClientHello(encode_raw(fixed(1, 1, 1, 0), none), &out), SG_PROTOCOL_ERROR);  // mode 0
    SG_EXPECT_STATUS(DecodeClientHello(encode_raw(fixed(1, 1, 1, 3), none), &out), SG_PROTOCOL_ERROR);  // mode 3

    // Invalid product strings.
    SG_EXPECT_STATUS(DecodeClientHello(encode_raw(fixed(1, 1, 1, 1),
                                                  [](ser::TlvWriter& t) { t.AddString(tlv::kProductId, "bad\nid"); }),
                                       &out),
                     SG_PROTOCOL_ERROR);
    SG_EXPECT_STATUS(DecodeClientHello(encode_raw(fixed(1, 1, 1, 1),
                                                  [](ser::TlvWriter& t) { t.Add(tlv::kProductId, ByteView()); }),
                                       &out),
                     SG_PROTOCOL_ERROR);
    SG_EXPECT_STATUS(DecodeClientHello(encode_raw(fixed(1, 1, 1, 1),
                                                  [](ser::TlvWriter& t) { t.AddString(tlv::kProductId, std::string(65, 'p')); }),
                                       &out),
                     SG_PROTOCOL_ERROR);
    // Wrong fixed-size TLV lengths.
    SG_EXPECT_STATUS(DecodeClientHello(encode_raw(fixed(1, 1, 1, 1),
                                                  [](ser::TlvWriter& t) { t.Add(tlv::kRequestedFeatures, Bytes(4, 0)); }),
                                       &out),
                     SG_PROTOCOL_ERROR);
    // Enrollment fields are forbidden in AUTHENTICATE mode...
    SG_EXPECT_STATUS(DecodeClientHello(encode_raw(fixed(1, 1, 1, 1),
                                                  [](ser::TlvWriter& t) { t.Add(tlv::kEnrollmentTokenId, Bytes(20, 1)); }),
                                       &out),
                     SG_PROTOCOL_ERROR);
    // ...and both are required in ENROLL mode.
    SG_EXPECT_STATUS(DecodeClientHello(encode_raw(fixed(1, 1, 1, 2),
                                                  [](ser::TlvWriter& t) { t.Add(tlv::kEnrollmentTokenId, Bytes(20, 1)); }),
                                       &out),
                     SG_PROTOCOL_ERROR);
    Bytes pub(65, 7);
    pub[0] = 0x04;
    SG_EXPECT_OK(DecodeClientHello(encode_raw(fixed(1, 1, 1, 2),
                                              [&](ser::TlvWriter& t) {
                                                  t.Add(tlv::kEnrollmentTokenId, Bytes(20, 1));
                                                  t.Add(tlv::kPublicKey, pub);
                                              }),
                                   &out));
    Bytes compressed = pub;
    compressed[0] = 0x02;
    SG_EXPECT_STATUS(DecodeClientHello(encode_raw(fixed(1, 1, 1, 2),
                                                  [&](ser::TlvWriter& t) {
                                                      t.Add(tlv::kEnrollmentTokenId, Bytes(20, 1));
                                                      t.Add(tlv::kPublicKey, compressed);
                                                  }),
                                       &out),
                     SG_PROTOCOL_ERROR);
    // Unknown extensions are ignored.
    SG_EXPECT_OK(DecodeClientHello(encode_raw(fixed(1, 1, 1, 1),
                                              [](ser::TlvWriter& t) { t.Add(999, Bytes(3, 0)); }),
                                   &out));
}

SG_TEST(Messages, ServerHelloAndProof)
{
    ServerHello sh;
    sh.server_nonce.fill(3);
    sh.challenge.fill(4);
    sh.challenge_ttl_ms = 30000;
    sh.server_proof_algorithm = kProofAlgorithmEcdsaP256Sha256;
    Bytes wire;
    SG_ASSERT_OK(EncodeServerHello(sh, &wire));
    ServerHello sh2;
    SG_ASSERT_OK(DecodeServerHello(wire, &sh2));
    SG_EXPECT(sh2.challenge == sh.challenge);
    ExpectTruncationAndTrailingRejected<ServerHello>(wire, &DecodeServerHello, "ServerHello");

    ServerHello zero_ttl = sh;
    zero_ttl.challenge_ttl_ms = 0;
    Bytes w2;
    SG_ASSERT_OK(EncodeServerHello(zero_ttl, &w2));
    SG_EXPECT_STATUS(DecodeServerHello(w2, &sh2), SG_PROTOCOL_ERROR);

    ClientProof cp;
    cp.signature.fill(9);
    cp.has_enrollment_proof = true;
    cp.enrollment_proof.fill(8);
    Bytes pw;
    SG_ASSERT_OK(EncodeClientProof(cp, &pw));
    ClientProof cp2;
    SG_ASSERT_OK(DecodeClientProof(pw, &cp2));
    SG_EXPECT(cp2.signature == cp.signature && cp2.has_enrollment_proof && cp2.enrollment_proof == cp.enrollment_proof);
    ExpectTruncationAndTrailingRejected<ClientProof>(pw, &DecodeClientProof, "ClientProof");

    // Signature length must be exactly 64.
    Bytes bad;
    ser::Writer w(&bad);
    w.U8(1);
    SG_ASSERT_OK(w.Vec16(Bytes(63, 1)));
    w.U16(0);
    SG_EXPECT_STATUS(DecodeClientProof(bad, &cp2), SG_PROTOCOL_ERROR);
}

SG_TEST(Messages, AuthResultRules)
{
    AuthResult ok;
    ok.result = AuthResultCode::kOk;
    ok.policy = SessionPolicy::kNormal;
    ok.granted_features = 3;
    ok.session_lifetime_ms = 3600000;
    ok.server_proof_algorithm = kProofAlgorithmEcdsaP256Sha256;
    ok.has_server_signature = true;
    ok.server_signature.fill(5);
    Bytes wire;
    SG_ASSERT_OK(EncodeAuthResult(ok, &wire));
    SG_EXPECT_EQ(wire.size(), kAuthResultSignedPayloadPrefix + 2 + 64);
    AuthResult out;
    SG_ASSERT_OK(DecodeAuthResult(wire, &out));
    SG_EXPECT(out.has_server_signature && out.server_signature == ok.server_signature);
    ExpectTruncationAndTrailingRejected<AuthResult>(wire, &DecodeAuthResult, "AuthResult");

    AuthResult rejected;
    rejected.result = AuthResultCode::kRejected;
    Bytes rw;
    SG_ASSERT_OK(EncodeAuthResult(rejected, &rw));
    SG_ASSERT_OK(DecodeAuthResult(rw, &out));
    SG_EXPECT(out.result == AuthResultCode::kRejected);

    // A rejection must not leak policy/feature data.
    AuthResult leaky = rejected;
    leaky.granted_features = 1;
    Bytes lw;
    SG_ASSERT_OK(EncodeAuthResult(leaky, &lw));
    SG_EXPECT_STATUS(DecodeAuthResult(lw, &out), SG_PROTOCOL_ERROR);

    // OK requires a policy and a lifetime.
    AuthResult no_lifetime = ok;
    no_lifetime.session_lifetime_ms = 0;
    Bytes nw;
    SG_ASSERT_OK(EncodeAuthResult(no_lifetime, &nw));
    SG_EXPECT_STATUS(DecodeAuthResult(nw, &out), SG_PROTOCOL_ERROR);

    // Unknown enum values.
    Bytes unknown = wire;
    unknown[0] = 9;
    SG_EXPECT_STATUS(DecodeAuthResult(unknown, &out), SG_PROTOCOL_ERROR);
    Bytes bad_alg = wire;
    bad_alg[kAuthResultSignedPayloadPrefix - 1] = 7;
    SG_EXPECT_STATUS(DecodeAuthResult(bad_alg, &out), SG_PROTOCOL_ERROR);
    // Algorithm says "signed" but no signature bytes.
    AuthResult inconsistent = ok;
    inconsistent.has_server_signature = false;
    Bytes iw;
    SG_EXPECT_STATUS(EncodeAuthResult(inconsistent, &iw), SG_INVALID_ARGUMENT);
}

SG_TEST(Messages, ControlMessages)
{
    Bytes w;
    SG_ASSERT_OK(EncodePingPong({0x1122334455667788ull}, &w));
    PingPong p;
    SG_ASSERT_OK(DecodePingPong(w, &p));
    SG_EXPECT_EQ(p.opaque, 0x1122334455667788ull);
    ExpectTruncationAndTrailingRejected<PingPong>(w, &DecodePingPong, "Ping");

    ReauthChallenge rc;
    rc.challenge_ttl_ms = 1000;
    Bytes rcw;
    SG_ASSERT_OK(EncodeReauthChallenge(rc, &rcw));
    ExpectTruncationAndTrailingRejected<ReauthChallenge>(rcw, &DecodeReauthChallenge, "ReauthChallenge");

    ReauthResult rr;
    rr.result = AuthResultCode::kOk;
    rr.session_lifetime_ms = 1000;
    rr.new_epoch = 1;
    Bytes rrw;
    SG_ASSERT_OK(EncodeReauthResult(rr, &rrw));
    ReauthResult rr2;
    SG_ASSERT_OK(DecodeReauthResult(rrw, &rr2));
    SG_EXPECT_EQ(rr2.new_epoch, 1u);
    rr.result = AuthResultCode::kUnsupportedVersion;
    Bytes uv;
    SG_ASSERT_OK(EncodeReauthResult(rr, &uv));
    SG_EXPECT_STATUS(DecodeReauthResult(uv, &rr2), SG_PROTOCOL_ERROR);

    Bytes cw;
    SG_ASSERT_OK(EncodeClose({CloseReason::kIdleTimeout}, &cw));
    CloseMessage cm;
    SG_ASSERT_OK(DecodeClose(cw, &cm));
    SG_EXPECT(cm.reason == CloseReason::kIdleTimeout);
    const Bytes unknown_reason = {0x00, 0x63};
    SG_EXPECT_STATUS(DecodeClose(unknown_reason, &cm), SG_PROTOCOL_ERROR);
}

SG_TEST(Rules, PhaseAndDirectionTable)
{
    FrameLimits limits;
    auto check = [&](MessageType t, Role r, Phase p, uint16_t auth, uint16_t flags = 0, uint32_t len = 0,
                     uint64_t request_id = 0) {
        FrameHeader h;
        h.type = t;
        h.auth_length = auth;
        h.flags = flags;
        h.payload_length = len;
        h.request_id = request_id;
        return CheckHeaderForState(h, r, p, limits);
    };
    const uint16_t tag = kAuthTagSize;
    // Handshake ordering.
    SG_EXPECT_OK(check(MessageType::kClientHello, Role::kServer, Phase::kAwaitClientHello, 0));
    SG_EXPECT(!check(MessageType::kClientHello, Role::kServer, Phase::kAwaitClientProof, 0).ok());
    SG_EXPECT(!check(MessageType::kClientProof, Role::kServer, Phase::kAwaitClientHello, 0).ok());
    SG_EXPECT(!check(MessageType::kServerHello, Role::kServer, Phase::kAwaitClientHello, 0).ok());  // wrong direction
    SG_EXPECT_OK(check(MessageType::kAuthResult, Role::kClient, Phase::kAwaitServerHello, 0));      // version mismatch path
    // No application data before authentication, whatever its size.
    SG_EXPECT(!check(MessageType::kData, Role::kServer, Phase::kAwaitClientHello, 0).ok());
    SG_EXPECT(!check(MessageType::kData, Role::kServer, Phase::kAwaitClientProof, tag).ok());
    // Auth tag mandatory after authentication, forbidden before.
    SG_EXPECT_OK(check(MessageType::kData, Role::kServer, Phase::kActive, tag));
    SG_EXPECT(!check(MessageType::kData, Role::kServer, Phase::kActive, 0).ok());
    SG_EXPECT(!check(MessageType::kClientHello, Role::kServer, Phase::kAwaitClientHello, tag).ok());
    // Flags are forbidden before authentication.
    SG_EXPECT(!check(MessageType::kClientHello, Role::kServer, Phase::kAwaitClientHello, 0, kFlagEncrypted).ok());
    // RESPONSE only on DATA and only with a request id.
    SG_EXPECT(!check(MessageType::kPing, Role::kServer, Phase::kActive, tag, kFlagResponse).ok());
    SG_EXPECT(!check(MessageType::kData, Role::kServer, Phase::kActive, tag, kFlagResponse, 0, 0).ok());
    SG_EXPECT_OK(check(MessageType::kData, Role::kServer, Phase::kActive, tag, kFlagResponse, 0, 5));
    SG_EXPECT(!check(MessageType::kPing, Role::kServer, Phase::kActive, tag, 0, 8, 3).ok());  // request id on PING
    // Size limits depend on the phase.
    SG_EXPECT(!check(MessageType::kClientHello, Role::kServer, Phase::kAwaitClientHello, 0, 0, kMaxHandshakePayload + 1).ok());
    SG_EXPECT_OK(check(MessageType::kData, Role::kServer, Phase::kActive, tag, 0, kDefaultMaxPayload));
    SG_EXPECT(!check(MessageType::kData, Role::kServer, Phase::kActive, tag, 0, kDefaultMaxPayload + 1).ok());
    SG_EXPECT(!check(MessageType::kPing, Role::kServer, Phase::kActive, tag, 0, kMaxHandshakePayload + 1).ok());
    // Reauthentication direction and phase.
    SG_EXPECT_OK(check(MessageType::kReauthRequest, Role::kServer, Phase::kActive, tag));
    SG_EXPECT(!check(MessageType::kReauthRequest, Role::kServer, Phase::kRefreshing, tag).ok());
    SG_EXPECT(!check(MessageType::kReauthRequest, Role::kClient, Phase::kActive, tag).ok());
    SG_EXPECT_OK(check(MessageType::kReauthProof, Role::kServer, Phase::kRefreshing, tag));
    SG_EXPECT_OK(check(MessageType::kReauthResult, Role::kClient, Phase::kRefreshing, tag));
    // CLOSE is always accepted with the matching auth length; nothing in kClosed.
    SG_EXPECT_OK(check(MessageType::kClose, Role::kClient, Phase::kAwaitAuthResult, 0));
    SG_EXPECT_OK(check(MessageType::kClose, Role::kClient, Phase::kActive, tag));
    SG_EXPECT(!check(MessageType::kClose, Role::kClient, Phase::kClosed, 0).ok());
}

SG_TEST(Rules, DispatcherRoutesByType)
{
    MessageDispatcher d;
    int pings = 0;
    d.On(MessageType::kPing, [&](const DecodedFrame&) {
        ++pings;
        return OkStatus();
    });
    FrameHeader h;
    h.type = MessageType::kPing;
    Bytes wire;
    SG_ASSERT_OK(EncodeFrame(h, Bytes(8, 0), ByteView(), &wire));
    FrameDecoder dec([](const FrameHeader&) { return OkStatus(); });
    SG_ASSERT_OK(dec.Append(wire));
    DecodedFrame f;
    bool ready = false;
    SG_ASSERT_OK(dec.Next(&f, &ready));
    SG_ASSERT(ready);
    SG_EXPECT_OK(d.Dispatch(f));
    SG_EXPECT_EQ(pings, 1);

    FrameHeader h2;
    h2.type = MessageType::kPong;
    Bytes wire2;
    SG_ASSERT_OK(EncodeFrame(h2, Bytes(8, 0), ByteView(), &wire2));
    SG_ASSERT_OK(dec.Append(wire2));
    SG_ASSERT_OK(dec.Next(&f, &ready));
    SG_EXPECT_STATUS(d.Dispatch(f), SG_PROTOCOL_ERROR);  // unregistered type
}

SG_TEST(EnrollmentToken, BuildParseAndTamper)
{
    const Bytes server_key(32, 0x42);
    EnrollmentClaims claims;
    claims.token_id.fill(0x01);
    claims.product_id = "example-product";
    claims.license_id = "LIC-1";
    claims.issued_at_ms = 1000;
    claims.expires_at_ms = 2000;
    std::string token;
    SG_ASSERT_OK(BuildEnrollmentToken(server_key, claims, &token));

    Bytes token_pub;
    crypto::Sha256Digest k_tok;
    SG_ASSERT_OK(ParseEnrollmentToken(token, &token_pub, &k_tok));
    EnrollmentClaims parsed;
    SG_ASSERT_OK(DecodeTokenPublic(token_pub, &parsed));
    SG_EXPECT_EQ(parsed.product_id, claims.product_id);
    SG_EXPECT_EQ(parsed.license_id, claims.license_id);
    SG_EXPECT(parsed.token_id == claims.token_id);

    // The server re-derives K_tok from token_pub; it matches only for the
    // untouched public part.
    crypto::Sha256Digest expected;
    SG_ASSERT_OK(DeriveEnrollmentKey(server_key, token_pub, &expected));
    SG_EXPECT(expected == k_tok);
    Bytes modified = token_pub;
    modified.back() ^= 0x01;  // extend the expiry
    crypto::Sha256Digest forged;
    SG_ASSERT_OK(DeriveEnrollmentKey(server_key, modified, &forged));
    SG_EXPECT(forged != k_tok);

    // A different server secret yields a different key.
    crypto::Sha256Digest other;
    SG_ASSERT_OK(DeriveEnrollmentKey(Bytes(32, 0x43), token_pub, &other));
    SG_EXPECT(other != k_tok);

    SG_EXPECT_STATUS(ParseEnrollmentToken("not*base64", &token_pub, &k_tok), SG_INVALID_ARGUMENT);
    SG_EXPECT_STATUS(ParseEnrollmentToken(token.substr(0, 20), &token_pub, &k_tok), SG_INVALID_ARGUMENT);
    SG_EXPECT_STATUS(ParseEnrollmentToken("", &token_pub, &k_tok), SG_INVALID_ARGUMENT);

    EnrollmentClaims bad = claims;
    bad.expires_at_ms = bad.issued_at_ms;
    SG_EXPECT_STATUS(BuildEnrollmentToken(server_key, bad, &token), SG_INVALID_ARGUMENT);
    SG_EXPECT_STATUS(BuildEnrollmentToken(Bytes(16, 1), claims, &token), SG_INVALID_ARGUMENT);  // short server key
}

SG_TEST(Transcript, HashesAndKeysAreDomainSeparated)
{
    crypto::Sha256Digest cb{};
    cb.fill(1);
    const Bytes ch = {1, 2, 3};
    const Bytes sh = {4, 5, 6};
    crypto::Sha256Digest a, b, c;
    SG_ASSERT_OK(ComputeTranscriptHash(1, cb, ch, sh, &a));
    SG_ASSERT_OK(ComputeTranscriptHash(1, cb, ch, sh, &b));
    SG_EXPECT(a == b);
    // Length prefixes prevent boundary-shifting ambiguity.
    const Bytes ch2 = {1, 2};
    const Bytes sh2 = {3, 4, 5, 6};
    SG_ASSERT_OK(ComputeTranscriptHash(1, cb, ch2, sh2, &c));
    SG_EXPECT(a != c);
    crypto::Sha256Digest cb2 = cb;
    cb2[0] ^= 1;
    SG_ASSERT_OK(ComputeTranscriptHash(1, cb2, ch, sh, &c));
    SG_EXPECT(a != c);

    const Bytes client_signed = SignedData(kClientProofContext, a);
    const Bytes server_signed = SignedData(kServerProofContext, a);
    SG_EXPECT(client_signed != server_signed);
    SG_EXPECT_EQ(client_signed.size(), std::strlen(kClientProofContext) + 1 + 32);

    SessionId sid{};
    sid.fill(9);
    const Bytes km(32, 7);
    crypto::AeadKey c2s0, s2c0, c2s1, s2c1;
    SG_ASSERT_OK(DeriveChannelKeys(km, sid, 0, &c2s0, &s2c0));
    SG_ASSERT_OK(DeriveChannelKeys(km, sid, 1, &c2s1, &s2c1));
    SG_EXPECT(c2s0 != s2c0);
    SG_EXPECT(c2s0 != c2s1);
    SG_EXPECT(s2c0 != s2c1);
    SessionId sid2 = sid;
    sid2[0] ^= 1;
    crypto::AeadKey c2s_other, s2c_other;
    SG_ASSERT_OK(DeriveChannelKeys(km, sid2, 0, &c2s_other, &s2c_other));
    SG_EXPECT(c2s0 != c2s_other);

    crypto::P256PublicKey pub{};
    pub[0] = 4;
    InstallationId iid1, iid2;
    SG_ASSERT_OK(DeriveInstallationId(pub, &iid1));
    pub[1] = 1;
    SG_ASSERT_OK(DeriveInstallationId(pub, &iid2));
    SG_EXPECT(iid1 != iid2);
}
