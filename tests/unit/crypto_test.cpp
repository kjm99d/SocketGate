#include "sg_test.h"

#include "sockgate_common/crypto/crypto.h"

#include <cstring>
#include <string>

using namespace sg;
using namespace sg::crypto;

namespace {

Bytes FromHex(const std::string& hex)
{
    Bytes out;
    for (size_t i = 0; i + 1 < hex.size(); i += 2) out.push_back(static_cast<uint8_t>(std::stoi(hex.substr(i, 2), nullptr, 16)));
    return out;
}

ByteView Str(const std::string& s) { return ByteView(reinterpret_cast<const uint8_t*>(s.data()), s.size()); }

template <size_t N>
std::string Hex(const std::array<uint8_t, N>& a)
{
    return ToHex(ByteView(a.data(), a.size()));
}

}  // namespace

SG_TEST(Crypto, Sha256KnownVector)
{
    Sha256Digest d;
    SG_ASSERT_OK(Sha256(Str("abc"), &d));
    SG_EXPECT_EQ(Hex(d), std::string("ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"));

    // Multi-part hashing equals one-shot hashing.
    Sha256Digest parts;
    SG_ASSERT_OK(Sha256({Str("a"), Str(""), Str("bc")}, &parts));
    SG_EXPECT(parts == d);

    Sha256Hasher h;
    SG_ASSERT_OK(h.Update(Str("ab")));
    SG_ASSERT_OK(h.Update(Str("c")));
    Sha256Digest inc;
    SG_ASSERT_OK(h.Final(&inc));
    SG_EXPECT(inc == d);
    SG_EXPECT_STATUS(h.Update(Str("x")), SG_INVALID_STATE);  // no reuse after Final
}

SG_TEST(Crypto, HmacRfc4231)
{
    Sha256Digest mac;
    const Bytes key1(20, 0x0b);
    SG_ASSERT_OK(HmacSha256(key1, {Str("Hi There")}, &mac));
    SG_EXPECT_EQ(Hex(mac), std::string("b0344c61d8db38535ca8afceaf0bf12b881dc200c9833da726e9376c2e32cff7"));

    SG_ASSERT_OK(HmacSha256(Str("Jefe"), {Str("what do ya "), Str("want for nothing?")}, &mac));
    SG_EXPECT_EQ(Hex(mac), std::string("5bdcc146bf60754e6a042426089575c75a003f089d2739839dec58b964ec3843"));
}

SG_TEST(Crypto, HkdfRfc5869)
{
    const Bytes ikm(22, 0x0b);
    const Bytes salt = FromHex("000102030405060708090a0b0c");
    const Bytes info = FromHex("f0f1f2f3f4f5f6f7f8f9");
    uint8_t okm[42];
    SG_ASSERT_OK(HkdfSha256(ikm, salt, info, okm, sizeof(okm)));
    SG_EXPECT_EQ(ToHex(ByteView(okm, sizeof(okm))),
                 std::string("3cb25f25faacd57a90434f64d0362f2a2d2d0a90cf1a5a4c5db02d56ecc4c5bf34007208d5b887185865"));

    // Test case 3: empty salt and info.
    SG_ASSERT_OK(HkdfSha256(ikm, ByteView(), ByteView(), okm, sizeof(okm)));
    SG_EXPECT_EQ(ToHex(ByteView(okm, sizeof(okm))),
                 std::string("8da4e775a563c18f715f802a063c5a31b8a11f5c5ee1879ec3454e5f3c738d2d9d201395faa4b61a96c8"));

    SG_EXPECT_STATUS(HkdfSha256(ikm, salt, info, okm, 0), SG_INVALID_ARGUMENT);
    SG_EXPECT_STATUS(HkdfSha256(ikm, salt, info, nullptr, 10), SG_INVALID_ARGUMENT);
}

SG_TEST(Crypto, AesGcmKnownVectors)
{
    const AeadKey key{};
    const AeadNonce nonce{};
    AeadTag tag;
    // GCM spec test case 13: empty plaintext.
    SG_ASSERT_OK(AesGcmSeal(key, nonce, ByteView(), ByteView(), nullptr, &tag));
    SG_EXPECT_EQ(Hex(tag), std::string("530f8afbc74536b9a963b4f1c4cb738b"));
    // Test case 14: 16 zero bytes.
    const Bytes pt(16, 0);
    Bytes ct(16);
    SG_ASSERT_OK(AesGcmSeal(key, nonce, ByteView(), pt, ct.data(), &tag));
    SG_EXPECT_EQ(ToHex(ct), std::string("cea7403d4d606b6e074ec5d3baf39d18"));
    SG_EXPECT_EQ(Hex(tag), std::string("d0d1c8a799996bf0265b98b5d48ab919"));
}

SG_TEST(Crypto, AesGcmRoundTripAndTamperDetection)
{
    AeadKey key;
    AeadNonce nonce;
    SG_ASSERT_OK(RandomArray(&key));
    SG_ASSERT_OK(RandomArray(&nonce));
    const std::string msg = "attack at dawn - sockgate";
    const std::string aad = "header";
    Bytes ct(msg.size());
    AeadTag tag;
    SG_ASSERT_OK(AesGcmSeal(key, nonce, Str(aad), Str(msg), ct.data(), &tag));

    Bytes pt(ct.size());
    SG_ASSERT_OK(AesGcmOpen(key, nonce, Str(aad), ct, tag, pt.data()));
    SG_EXPECT(std::string(pt.begin(), pt.end()) == msg);

    Bytes bad_ct = ct;
    bad_ct[0] ^= 1;
    SG_EXPECT_STATUS(AesGcmOpen(key, nonce, Str(aad), bad_ct, tag, pt.data()), SG_CRYPTO_ERROR);
    // Output is wiped on failure.
    bool all_zero = true;
    for (uint8_t b : pt) all_zero = all_zero && b == 0;
    SG_EXPECT(all_zero);

    AeadTag bad_tag = tag;
    bad_tag[15] ^= 0x80;
    SG_EXPECT_STATUS(AesGcmOpen(key, nonce, Str(aad), ct, bad_tag, pt.data()), SG_CRYPTO_ERROR);
    SG_EXPECT_STATUS(AesGcmOpen(key, nonce, Str("Header"), ct, tag, pt.data()), SG_CRYPTO_ERROR);
    AeadNonce other_nonce = nonce;
    other_nonce[11] ^= 1;
    SG_EXPECT_STATUS(AesGcmOpen(key, other_nonce, Str(aad), ct, tag, pt.data()), SG_CRYPTO_ERROR);
    AeadKey other_key = key;
    other_key[0] ^= 1;
    SG_EXPECT_STATUS(AesGcmOpen(other_key, nonce, Str(aad), ct, tag, pt.data()), SG_CRYPTO_ERROR);
}

SG_TEST(Crypto, GmacAuthenticatesAadOnly)
{
    AeadKey key;
    AeadNonce nonce{};
    SG_ASSERT_OK(RandomArray(&key));
    AeadTag tag;
    SG_ASSERT_OK(AesGcmSeal(key, nonce, Str("header+payload"), ByteView(), nullptr, &tag));
    SG_EXPECT_OK(AesGcmOpen(key, nonce, Str("header+payload"), ByteView(), tag, nullptr));
    SG_EXPECT_STATUS(AesGcmOpen(key, nonce, Str("header+payloaD"), ByteView(), tag, nullptr), SG_CRYPTO_ERROR);
}

SG_TEST(Crypto, EcdsaSignVerify)
{
    std::unique_ptr<SoftwareP256Key> key;
    SG_ASSERT_OK(SoftwareP256Key::Generate(&key));
    P256PublicKey pub;
    SG_ASSERT_OK(key->PublicKey(&pub));
    SG_EXPECT_EQ(pub[0], 0x04);
    SG_EXPECT_OK(ValidateP256PublicKey(pub));

    P256Signature sig;
    SG_ASSERT_OK(key->Sign(Str("transcript"), &sig));
    SG_EXPECT_OK(VerifyP256(pub, Str("transcript"), sig));
    SG_EXPECT_STATUS(VerifyP256(pub, Str("transcripT"), sig), SG_INVALID_SIGNATURE);

    P256Signature bad = sig;
    bad[40] ^= 0x01;
    SG_EXPECT_STATUS(VerifyP256(pub, Str("transcript"), bad), SG_INVALID_SIGNATURE);

    std::unique_ptr<SoftwareP256Key> other;
    SG_ASSERT_OK(SoftwareP256Key::Generate(&other));
    P256PublicKey other_pub;
    SG_ASSERT_OK(other->PublicKey(&other_pub));
    SG_EXPECT_STATUS(VerifyP256(other_pub, Str("transcript"), sig), SG_INVALID_SIGNATURE);

    // Wrong signature length and all-zero (r = s = 0) signatures are rejected.
    SG_EXPECT_STATUS(VerifyP256(pub, Str("transcript"), ByteView(sig.data(), 63)), SG_INVALID_SIGNATURE);
    const P256Signature zero{};
    SG_EXPECT_STATUS(VerifyP256(pub, Str("transcript"), zero), SG_INVALID_SIGNATURE);
}

SG_TEST(Crypto, InvalidPublicKeysRejected)
{
    std::unique_ptr<SoftwareP256Key> key;
    SG_ASSERT_OK(SoftwareP256Key::Generate(&key));
    P256PublicKey pub;
    SG_ASSERT_OK(key->PublicKey(&pub));

    P256PublicKey off_curve = pub;
    off_curve[64] ^= 0x01;  // y no longer satisfies the curve equation
    SG_EXPECT(!ValidateP256PublicKey(off_curve).ok());

    P256PublicKey bad_prefix = pub;
    bad_prefix[0] = 0x02;  // compressed prefix is not accepted
    SG_EXPECT(!ValidateP256PublicKey(bad_prefix).ok());

    SG_EXPECT(!ValidateP256PublicKey(ByteView(pub.data(), 64)).ok());
    P256PublicKey infinity{};
    infinity[0] = 0x04;
    SG_EXPECT(!ValidateP256PublicKey(infinity).ok());

    P256Signature sig;
    SG_ASSERT_OK(key->Sign(Str("m"), &sig));
    SG_EXPECT_STATUS(VerifyP256(off_curve, Str("m"), sig), SG_INVALID_SIGNATURE);
}

SG_TEST(Crypto, SignatureEncodings)
{
    std::unique_ptr<SoftwareP256Key> key;
    SG_ASSERT_OK(SoftwareP256Key::Generate(&key));
    P256Signature sig;
    SG_ASSERT_OK(key->Sign(Str("m"), &sig));
    Bytes der;
    SG_ASSERT_OK(EcdsaP1363ToDer(sig, &der));
    P256Signature back;
    SG_ASSERT_OK(EcdsaDerToP1363(der, &back));
    SG_EXPECT(back == sig);

    Bytes trailing = der;
    trailing.push_back(0);
    SG_EXPECT_STATUS(EcdsaDerToP1363(trailing, &back), SG_INVALID_SIGNATURE);
    Bytes truncated(der.begin(), der.end() - 1);
    SG_EXPECT_STATUS(EcdsaDerToP1363(truncated, &back), SG_INVALID_SIGNATURE);
}

SG_TEST(Crypto, Pkcs8AndPemRoundTrip)
{
    std::unique_ptr<SoftwareP256Key> key;
    SG_ASSERT_OK(SoftwareP256Key::Generate(&key));
    SecureBytes der;
    SG_ASSERT_OK(key->ToPkcs8Der(&der));
    std::unique_ptr<SoftwareP256Key> loaded;
    SG_ASSERT_OK(SoftwareP256Key::FromPkcs8Der(der, &loaded));
    P256PublicKey a, b;
    SG_ASSERT_OK(key->PublicKey(&a));
    SG_ASSERT_OK(loaded->PublicKey(&b));
    SG_EXPECT(a == b);

    std::unique_ptr<SoftwareP256Key> bad;
    SG_EXPECT(!SoftwareP256Key::FromPkcs8Der(ByteView(der.data(), 10), &bad).ok());
    SecureBytes trailing = der;
    trailing.push_back(0);
    SG_EXPECT(!SoftwareP256Key::FromPkcs8Der(trailing, &bad).ok());
    SG_EXPECT(!SoftwareP256Key::FromPem(Str("-----BEGIN PRIVATE KEY-----\nAAAA\n-----END PRIVATE KEY-----\n"), &bad).ok());
}

SG_TEST(Crypto, RandomBytesLookRandom)
{
    std::array<uint8_t, 32> a{}, b{};
    SG_ASSERT_OK(RandomArray(&a));
    SG_ASSERT_OK(RandomArray(&b));
    SG_EXPECT(a != b);
    SG_EXPECT(a != (std::array<uint8_t, 32>{}));
    SG_EXPECT_STATUS(RandomBytes(nullptr, 4), SG_INVALID_ARGUMENT);
    SG_EXPECT_OK(RandomBytes(nullptr, 0));
}
