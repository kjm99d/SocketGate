// Fuzz target: message payload decoders, integrity reports and enrollment
// tokens. Byte 0 selects the decoder. Successfully decoded messages are
// re-encoded and decoded again; the round trip must be stable.
#include "fuzz_target.h"

#include "sockgate_common/protocol/enrollment_token.h"
#include "sockgate_common/protocol/messages.h"
#include "sockgate_common/serialization/base64.h"
#include "sockgate_common/serialization/writer.h"

#include <algorithm>
#include <cstdlib>
#include <string>

using namespace sg;
using namespace sg::proto;

namespace {

void Check(bool condition)
{
    if (!condition) std::abort();
}

template <class T>
void RoundTrip(ByteView in, Status (*decode)(ByteView, T*), Status (*encode)(const T&, Bytes*))
{
    T first;
    if (!decode(in, &first).ok()) return;
    Bytes again;
    Check(encode(first, &again).ok());
    T second;
    Check(decode(again, &second).ok());
    Bytes third;
    Check(encode(second, &third).ok());
    Check(again == third);
}

}  // namespace

extern "C" int LLVMFuzzerTestOneInput(const uint8_t* data, size_t size)
{
    if (size < 1) return 0;
    const uint8_t selector = data[0];
    const ByteView in(data + 1, size - 1);
    switch (selector % 12) {
    case 0: RoundTrip<ClientHello>(in, &DecodeClientHello, &EncodeClientHello); break;
    case 1: RoundTrip<ServerHello>(in, &DecodeServerHello, &EncodeServerHello); break;
    case 2: RoundTrip<ClientProof>(in, &DecodeClientProof, &EncodeClientProof); break;
    case 3: RoundTrip<AuthResult>(in, &DecodeAuthResult, &EncodeAuthResult); break;
    case 4: RoundTrip<ReauthChallenge>(in, &DecodeReauthChallenge, &EncodeReauthChallenge); break;
    case 5: RoundTrip<ReauthProof>(in, &DecodeReauthProof, &EncodeReauthProof); break;
    case 6: RoundTrip<ReauthResult>(in, &DecodeReauthResult, &EncodeReauthResult); break;
    case 7: RoundTrip<CloseMessage>(in, &DecodeClose, &EncodeClose); break;
    case 8: RoundTrip<IntegrityReport>(in, &DecodeIntegrityReport, &EncodeIntegrityReport); break;
    case 9: {
        EnrollmentClaims claims;
        if (DecodeTokenPublic(in, &claims).ok()) {
            Bytes again;
            Check(EncodeTokenPublic(claims, &again).ok());
            Check(ByteView(again).size() == in.size() && std::equal(again.begin(), again.end(), in.begin()));
        }
        break;
    }
    case 10: {
        const std::string text(reinterpret_cast<const char*>(in.data()), in.size());
        Bytes token_pub;
        crypto::Sha256Digest k_tok;
        (void)ParseEnrollmentToken(text, &token_pub, &k_tok);
        break;
    }
    default: {
        const std::string text(reinterpret_cast<const char*>(in.data()), in.size());
        SecureBytes decoded;
        if (ser::Base64UrlDecode(text, &decoded).ok()) {
            Check(ser::Base64UrlEncode(ByteView(decoded)) == text);
        }
        break;
    }
    }
    return 0;
}

std::vector<std::vector<uint8_t>> SockGateFuzzSeeds()
{
    std::vector<std::vector<uint8_t>> seeds;
    auto add = [&](uint8_t selector, const Bytes& payload) {
        Bytes s = {selector};
        s.insert(s.end(), payload.begin(), payload.end());
        seeds.push_back(s);
    };
    ClientHello ch;
    ch.product_id = "product";
    ch.license_id = "L";
    ch.has_integrity = true;
    ch.integrity.platform = 2;
    Bytes b;
    (void)EncodeClientHello(ch, &b);
    add(0, b);

    ClientHello enroll;
    enroll.auth_mode = AuthMode::kEnroll;
    enroll.enrollment_token_id = Bytes(40, 3);
    enroll.has_public_key = true;
    enroll.public_key[0] = 4;
    b.clear();
    (void)EncodeClientHello(enroll, &b);
    add(0, b);

    ServerHello sh;
    sh.challenge_ttl_ms = 10;
    b.clear();
    (void)EncodeServerHello(sh, &b);
    add(1, b);

    ClientProof cp;
    cp.has_enrollment_proof = true;
    b.clear();
    (void)EncodeClientProof(cp, &b);
    add(2, b);

    AuthResult ar;
    ar.result = AuthResultCode::kOk;
    ar.policy = SessionPolicy::kRestricted;
    ar.session_lifetime_ms = 10;
    ar.server_proof_algorithm = kProofAlgorithmEcdsaP256Sha256;
    ar.has_server_signature = true;
    b.clear();
    (void)EncodeAuthResult(ar, &b);
    add(3, b);

    ReauthResult rr;
    rr.result = AuthResultCode::kOk;
    rr.session_lifetime_ms = 1;
    rr.new_epoch = 2;
    b.clear();
    (void)EncodeReauthResult(rr, &b);
    add(6, b);

    EnrollmentClaims claims;
    claims.product_id = "p";
    claims.issued_at_ms = 1;
    claims.expires_at_ms = 2;
    b.clear();
    (void)EncodeTokenPublic(claims, &b);
    add(9, b);

    std::string token;
    (void)BuildEnrollmentToken(Bytes(32, 1), claims, &token);
    const ByteView token_bytes = sg::ser::AsBytes(token);
    add(10, Bytes(token_bytes.begin(), token_bytes.end()));
    add(11, Bytes({'Q', 'U', 'J', 'D'}));
    return seeds;
}
