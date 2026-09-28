// OpenSSL 3.x implementation of sockgate_common/crypto/crypto.h.
// Only EVP-level, non-deprecated APIs are used.
#include "sockgate_common/crypto/crypto.h"

#include <openssl/bn.h>
#include <openssl/core_names.h>
#include <openssl/crypto.h>
#include <openssl/ec.h>
#include <openssl/err.h>
#include <openssl/evp.h>
#include <openssl/kdf.h>
#include <openssl/params.h>
#include <openssl/pem.h>
#include <openssl/rand.h>
#include <openssl/x509.h>

#include <climits>
#include <cstring>
#include <string>

namespace sg::crypto {
namespace {

// Small RAII helpers for OpenSSL objects.
struct EvpMdCtxDeleter { void operator()(EVP_MD_CTX* p) const { EVP_MD_CTX_free(p); } };
struct EvpCipherCtxDeleter { void operator()(EVP_CIPHER_CTX* p) const { EVP_CIPHER_CTX_free(p); } };
struct EvpPkeyDeleter { void operator()(EVP_PKEY* p) const { EVP_PKEY_free(p); } };
struct EvpPkeyCtxDeleter { void operator()(EVP_PKEY_CTX* p) const { EVP_PKEY_CTX_free(p); } };
struct EvpMacDeleter { void operator()(EVP_MAC* p) const { EVP_MAC_free(p); } };
struct EvpMacCtxDeleter { void operator()(EVP_MAC_CTX* p) const { EVP_MAC_CTX_free(p); } };
struct EvpKdfDeleter { void operator()(EVP_KDF* p) const { EVP_KDF_free(p); } };
struct EvpKdfCtxDeleter { void operator()(EVP_KDF_CTX* p) const { EVP_KDF_CTX_free(p); } };
struct EcdsaSigDeleter { void operator()(ECDSA_SIG* p) const { ECDSA_SIG_free(p); } };
struct BioDeleter { void operator()(BIO* p) const { BIO_free(p); } };
struct P8Deleter { void operator()(PKCS8_PRIV_KEY_INFO* p) const { PKCS8_PRIV_KEY_INFO_free(p); } };

using MdCtxPtr = std::unique_ptr<EVP_MD_CTX, EvpMdCtxDeleter>;
using CipherCtxPtr = std::unique_ptr<EVP_CIPHER_CTX, EvpCipherCtxDeleter>;
using PkeyPtr = std::unique_ptr<EVP_PKEY, EvpPkeyDeleter>;
using PkeyCtxPtr = std::unique_ptr<EVP_PKEY_CTX, EvpPkeyCtxDeleter>;
using EcdsaSigPtr = std::unique_ptr<ECDSA_SIG, EcdsaSigDeleter>;

// Every public entry point clears the thread's OpenSSL error queue on exit so
// stale errors never leak into unrelated SSL_get_error() calls.
struct ErrorQueueGuard {
    ~ErrorQueueGuard() { ERR_clear_error(); }
};

bool FitsInt(size_t n) { return n <= static_cast<size_t>(INT_MAX); }

// Non-null pointer for zero-length inputs (some OpenSSL APIs reject NULL).
const uint8_t kEmpty[1] = {0};
const uint8_t* PtrOrEmpty(ByteView v) { return v.data() != nullptr ? v.data() : kEmpty; }

int NoPasswordCallback(char*, int, int, void*) { return 0; }  // never prompt on a console

Status BuildP256PublicKey(ByteView sec1, PkeyPtr* out)
{
    if (sec1.size() != kP256PublicKeySize || sec1[0] != 0x04) return SG_INVALID_ARGUMENT;
    PkeyCtxPtr ctx(EVP_PKEY_CTX_new_from_name(nullptr, "EC", nullptr));
    if (!ctx || EVP_PKEY_fromdata_init(ctx.get()) <= 0) return SG_CRYPTO_ERROR;

    char group[] = "prime256v1";
    OSSL_PARAM params[] = {
        OSSL_PARAM_construct_utf8_string(OSSL_PKEY_PARAM_GROUP_NAME, group, 0),
        OSSL_PARAM_construct_octet_string(OSSL_PKEY_PARAM_PUB_KEY, const_cast<uint8_t*>(sec1.data()), sec1.size()),
        OSSL_PARAM_construct_end(),
    };
    EVP_PKEY* raw = nullptr;
    if (EVP_PKEY_fromdata(ctx.get(), &raw, EVP_PKEY_PUBLIC_KEY, params) <= 0 || raw == nullptr) {
        return SG_INVALID_ARGUMENT;
    }
    PkeyPtr pkey(raw);

    // Explicit on-curve / not-infinity validation.
    PkeyCtxPtr check(EVP_PKEY_CTX_new_from_pkey(nullptr, pkey.get(), nullptr));
    if (!check || EVP_PKEY_public_check(check.get()) != 1) return SG_INVALID_ARGUMENT;
    *out = std::move(pkey);
    return OkStatus();
}

bool IsP256(EVP_PKEY* pkey)
{
    if (pkey == nullptr || !EVP_PKEY_is_a(pkey, "EC")) return false;
    char name[64] = {};
    size_t len = 0;
    if (EVP_PKEY_get_utf8_string_param(pkey, OSSL_PKEY_PARAM_GROUP_NAME, name, sizeof(name), &len) != 1) return false;
    const std::string group(name, len);
    return group == "prime256v1" || group == "P-256" || group == "secp256r1";
}

Status PrepareSoftwareKey(EVP_PKEY* pkey)
{
    if (!IsP256(pkey)) return SG_INVALID_ARGUMENT;
    char uncompressed[] = OSSL_PKEY_EC_POINT_CONVERSION_FORMAT_UNCOMPRESSED;
    if (EVP_PKEY_set_utf8_string_param(pkey, OSSL_PKEY_PARAM_EC_POINT_CONVERSION_FORMAT, uncompressed) != 1) {
        return SG_CRYPTO_ERROR;
    }
    return OkStatus();
}

}  // namespace

// ---- Random -----------------------------------------------------------------

Status RandomBytes(uint8_t* out, size_t size)
{
    ErrorQueueGuard guard;
    if (out == nullptr && size != 0) return SG_INVALID_ARGUMENT;
    while (size > 0) {
        const int chunk = size > static_cast<size_t>(INT_MAX) ? INT_MAX : static_cast<int>(size);
        if (RAND_bytes(out, chunk) != 1) return SG_CRYPTO_ERROR;
        out += chunk;
        size -= static_cast<size_t>(chunk);
    }
    return OkStatus();
}

// ---- SHA-256 ----------------------------------------------------------------

Status Sha256(ByteView data, Sha256Digest* out)
{
    return Sha256({data}, out);
}

Status Sha256(std::initializer_list<ByteView> parts, Sha256Digest* out)
{
    if (out == nullptr) return SG_INVALID_ARGUMENT;
    Sha256Hasher h;
    for (const ByteView& p : parts) SG_TRY(h.Update(p));
    return h.Final(out);
}

struct Sha256Hasher::Impl {
    MdCtxPtr ctx{EVP_MD_CTX_new()};
};

Sha256Hasher::Sha256Hasher() : impl_(std::make_unique<Impl>())
{
    ErrorQueueGuard guard;
    if (!impl_->ctx || EVP_DigestInit_ex(impl_->ctx.get(), EVP_sha256(), nullptr) != 1) status_ = SG_CRYPTO_ERROR;
}

Sha256Hasher::~Sha256Hasher() = default;

Status Sha256Hasher::Update(ByteView data)
{
    if (!status_.ok()) return status_;
    if (data.empty()) return OkStatus();
    ErrorQueueGuard guard;
    if (EVP_DigestUpdate(impl_->ctx.get(), data.data(), data.size()) != 1) status_ = SG_CRYPTO_ERROR;
    return status_;
}

Status Sha256Hasher::UpdateU16(uint16_t v)
{
    const uint8_t b[2] = {static_cast<uint8_t>(v >> 8), static_cast<uint8_t>(v)};
    return Update(ByteView(b, sizeof(b)));
}

Status Sha256Hasher::UpdateU32(uint32_t v)
{
    const uint8_t b[4] = {static_cast<uint8_t>(v >> 24), static_cast<uint8_t>(v >> 16), static_cast<uint8_t>(v >> 8),
                          static_cast<uint8_t>(v)};
    return Update(ByteView(b, sizeof(b)));
}

Status Sha256Hasher::UpdateWithLength(ByteView data)
{
    if (data.size() > 0xFFFFFFFFu) return SG_INVALID_ARGUMENT;
    SG_TRY(UpdateU32(static_cast<uint32_t>(data.size())));
    return Update(data);
}

Status Sha256Hasher::Final(Sha256Digest* out)
{
    if (out == nullptr) return SG_INVALID_ARGUMENT;
    if (!status_.ok()) return status_;
    ErrorQueueGuard guard;
    unsigned int len = 0;
    if (EVP_DigestFinal_ex(impl_->ctx.get(), out->data(), &len) != 1 || len != kSha256Size) {
        status_ = SG_CRYPTO_ERROR;
        return status_;
    }
    status_ = SG_INVALID_STATE;  // finalised: further use is an error
    return OkStatus();
}

// ---- HMAC / HKDF ------------------------------------------------------------

Status HmacSha256(ByteView key, std::initializer_list<ByteView> parts, Sha256Digest* out)
{
    if (out == nullptr) return SG_INVALID_ARGUMENT;
    ErrorQueueGuard guard;
    std::unique_ptr<EVP_MAC, EvpMacDeleter> mac(EVP_MAC_fetch(nullptr, "HMAC", nullptr));
    if (!mac) return SG_CRYPTO_ERROR;
    std::unique_ptr<EVP_MAC_CTX, EvpMacCtxDeleter> ctx(EVP_MAC_CTX_new(mac.get()));
    if (!ctx) return SG_CRYPTO_ERROR;
    char digest[] = "SHA256";
    OSSL_PARAM params[] = {
        OSSL_PARAM_construct_utf8_string(OSSL_MAC_PARAM_DIGEST, digest, 0),
        OSSL_PARAM_construct_end(),
    };
    if (EVP_MAC_init(ctx.get(), PtrOrEmpty(key), key.size(), params) != 1) return SG_CRYPTO_ERROR;
    for (const ByteView& p : parts) {
        if (!p.empty() && EVP_MAC_update(ctx.get(), p.data(), p.size()) != 1) return SG_CRYPTO_ERROR;
    }
    size_t len = 0;
    if (EVP_MAC_final(ctx.get(), out->data(), &len, out->size()) != 1 || len != kSha256Size) return SG_CRYPTO_ERROR;
    return OkStatus();
}

Status HkdfSha256(ByteView ikm, ByteView salt, ByteView info, uint8_t* out, size_t out_len)
{
    if (out == nullptr || out_len == 0 || out_len > 255 * kSha256Size) return SG_INVALID_ARGUMENT;
    ErrorQueueGuard guard;
    std::unique_ptr<EVP_KDF, EvpKdfDeleter> kdf(EVP_KDF_fetch(nullptr, "HKDF", nullptr));
    if (!kdf) return SG_CRYPTO_ERROR;
    std::unique_ptr<EVP_KDF_CTX, EvpKdfCtxDeleter> ctx(EVP_KDF_CTX_new(kdf.get()));
    if (!ctx) return SG_CRYPTO_ERROR;

    char digest[] = "SHA256";
    OSSL_PARAM params[5];
    size_t n = 0;
    params[n++] = OSSL_PARAM_construct_utf8_string(OSSL_KDF_PARAM_DIGEST, digest, 0);
    params[n++] = OSSL_PARAM_construct_octet_string(OSSL_KDF_PARAM_KEY, const_cast<uint8_t*>(PtrOrEmpty(ikm)), ikm.size());
    // An absent salt means HashLen zero bytes (RFC 5869 §2.2).
    if (!salt.empty()) {
        params[n++] = OSSL_PARAM_construct_octet_string(OSSL_KDF_PARAM_SALT, const_cast<uint8_t*>(salt.data()), salt.size());
    }
    if (!info.empty()) {
        params[n++] = OSSL_PARAM_construct_octet_string(OSSL_KDF_PARAM_INFO, const_cast<uint8_t*>(info.data()), info.size());
    }
    params[n] = OSSL_PARAM_construct_end();
    if (EVP_KDF_derive(ctx.get(), out, out_len, params) != 1) {
        SecureZero(out, out_len);
        return SG_CRYPTO_ERROR;
    }
    return OkStatus();
}

// ---- AES-256-GCM ------------------------------------------------------------

Status AesGcmSeal(const AeadKey& key, const AeadNonce& nonce, ByteView aad, ByteView plaintext,
                  uint8_t* ciphertext_out, AeadTag* tag_out)
{
    if (tag_out == nullptr || (ciphertext_out == nullptr && !plaintext.empty())) return SG_INVALID_ARGUMENT;
    if (!FitsInt(aad.size()) || !FitsInt(plaintext.size())) return SG_INVALID_ARGUMENT;
    ErrorQueueGuard guard;
    CipherCtxPtr ctx(EVP_CIPHER_CTX_new());
    if (!ctx) return SG_OUT_OF_MEMORY;
    int len = 0;
    if (EVP_EncryptInit_ex(ctx.get(), EVP_aes_256_gcm(), nullptr, nullptr, nullptr) != 1 ||
        EVP_CIPHER_CTX_ctrl(ctx.get(), EVP_CTRL_GCM_SET_IVLEN, static_cast<int>(kAeadNonceSize), nullptr) != 1 ||
        EVP_EncryptInit_ex(ctx.get(), nullptr, nullptr, key.data(), nonce.data()) != 1) {
        return SG_CRYPTO_ERROR;
    }
    if (!aad.empty() && EVP_EncryptUpdate(ctx.get(), nullptr, &len, aad.data(), static_cast<int>(aad.size())) != 1) {
        return SG_CRYPTO_ERROR;
    }
    int written = 0;
    if (!plaintext.empty()) {
        if (EVP_EncryptUpdate(ctx.get(), ciphertext_out, &len, plaintext.data(), static_cast<int>(plaintext.size())) != 1) {
            return SG_CRYPTO_ERROR;
        }
        written = len;
    }
    uint8_t final_block[16];
    if (EVP_EncryptFinal_ex(ctx.get(), ciphertext_out != nullptr ? ciphertext_out + written : final_block, &len) != 1 ||
        EVP_CIPHER_CTX_ctrl(ctx.get(), EVP_CTRL_GCM_GET_TAG, static_cast<int>(kAeadTagSize), tag_out->data()) != 1) {
        return SG_CRYPTO_ERROR;
    }
    return OkStatus();
}

Status AesGcmOpen(const AeadKey& key, const AeadNonce& nonce, ByteView aad, ByteView ciphertext,
                  const AeadTag& tag, uint8_t* plaintext_out)
{
    if (plaintext_out == nullptr && !ciphertext.empty()) return SG_INVALID_ARGUMENT;
    if (!FitsInt(aad.size()) || !FitsInt(ciphertext.size())) return SG_INVALID_ARGUMENT;
    ErrorQueueGuard guard;
    CipherCtxPtr ctx(EVP_CIPHER_CTX_new());
    if (!ctx) return SG_OUT_OF_MEMORY;
    int len = 0;
    if (EVP_DecryptInit_ex(ctx.get(), EVP_aes_256_gcm(), nullptr, nullptr, nullptr) != 1 ||
        EVP_CIPHER_CTX_ctrl(ctx.get(), EVP_CTRL_GCM_SET_IVLEN, static_cast<int>(kAeadNonceSize), nullptr) != 1 ||
        EVP_DecryptInit_ex(ctx.get(), nullptr, nullptr, key.data(), nonce.data()) != 1) {
        return SG_CRYPTO_ERROR;
    }
    if (!aad.empty() && EVP_DecryptUpdate(ctx.get(), nullptr, &len, aad.data(), static_cast<int>(aad.size())) != 1) {
        return SG_CRYPTO_ERROR;
    }
    int written = 0;
    if (!ciphertext.empty()) {
        if (EVP_DecryptUpdate(ctx.get(), plaintext_out, &len, ciphertext.data(), static_cast<int>(ciphertext.size())) != 1) {
            SecureZero(plaintext_out, ciphertext.size());
            return SG_CRYPTO_ERROR;
        }
        written = len;
    }
    AeadTag tag_copy = tag;  // the ctrl API takes a non-const pointer
    uint8_t final_block[16];
    if (EVP_CIPHER_CTX_ctrl(ctx.get(), EVP_CTRL_GCM_SET_TAG, static_cast<int>(kAeadTagSize), tag_copy.data()) != 1 ||
        EVP_DecryptFinal_ex(ctx.get(), plaintext_out != nullptr ? plaintext_out + written : final_block, &len) != 1) {
        if (plaintext_out != nullptr) SecureZero(plaintext_out, ciphertext.size());
        return SG_CRYPTO_ERROR;
    }
    return OkStatus();
}

// ---- ECDSA P-256 ------------------------------------------------------------

Status ValidateP256PublicKey(ByteView sec1)
{
    ErrorQueueGuard guard;
    PkeyPtr pkey;
    return BuildP256PublicKey(sec1, &pkey);
}

Status EcdsaP1363ToDer(ByteView p1363, Bytes* der_out)
{
    if (der_out == nullptr || p1363.size() != kP256SignatureSize) return SG_INVALID_ARGUMENT;
    ErrorQueueGuard guard;
    EcdsaSigPtr sig(ECDSA_SIG_new());
    if (!sig) return SG_OUT_OF_MEMORY;
    BIGNUM* r = BN_bin2bn(p1363.data(), static_cast<int>(kP256ScalarSize), nullptr);
    BIGNUM* s = BN_bin2bn(p1363.data() + kP256ScalarSize, static_cast<int>(kP256ScalarSize), nullptr);
    if (r == nullptr || s == nullptr || BN_is_zero(r) || BN_is_zero(s) || ECDSA_SIG_set0(sig.get(), r, s) != 1) {
        BN_free(r);
        BN_free(s);
        return SG_INVALID_SIGNATURE;
    }
    const int len = i2d_ECDSA_SIG(sig.get(), nullptr);
    if (len <= 0) return SG_CRYPTO_ERROR;
    der_out->resize(static_cast<size_t>(len));
    uint8_t* p = der_out->data();
    if (i2d_ECDSA_SIG(sig.get(), &p) != len) return SG_CRYPTO_ERROR;
    return OkStatus();
}

Status EcdsaDerToP1363(ByteView der, P256Signature* out)
{
    if (out == nullptr || der.empty() || !FitsInt(der.size())) return SG_INVALID_ARGUMENT;
    ErrorQueueGuard guard;
    const unsigned char* p = der.data();
    EcdsaSigPtr sig(d2i_ECDSA_SIG(nullptr, &p, static_cast<long>(der.size())));
    if (!sig || p != der.data() + der.size()) return SG_INVALID_SIGNATURE;
    const BIGNUM* r = nullptr;
    const BIGNUM* s = nullptr;
    ECDSA_SIG_get0(sig.get(), &r, &s);
    if (r == nullptr || s == nullptr || BN_num_bytes(r) > static_cast<int>(kP256ScalarSize) ||
        BN_num_bytes(s) > static_cast<int>(kP256ScalarSize) ||
        BN_bn2binpad(r, out->data(), static_cast<int>(kP256ScalarSize)) != static_cast<int>(kP256ScalarSize) ||
        BN_bn2binpad(s, out->data() + kP256ScalarSize, static_cast<int>(kP256ScalarSize)) != static_cast<int>(kP256ScalarSize)) {
        return SG_INVALID_SIGNATURE;
    }
    return OkStatus();
}

Status VerifyP256(ByteView sec1_public_key, ByteView message, ByteView signature)
{
    ErrorQueueGuard guard;
    if (signature.size() != kP256SignatureSize) return SG_INVALID_SIGNATURE;
    PkeyPtr pkey;
    if (!BuildP256PublicKey(sec1_public_key, &pkey).ok()) return SG_INVALID_SIGNATURE;
    Bytes der;
    if (!EcdsaP1363ToDer(signature, &der).ok()) return SG_INVALID_SIGNATURE;

    MdCtxPtr md(EVP_MD_CTX_new());
    if (!md) return SG_OUT_OF_MEMORY;
    if (EVP_DigestVerifyInit(md.get(), nullptr, EVP_sha256(), nullptr, pkey.get()) != 1) return SG_CRYPTO_ERROR;
    const int rc = EVP_DigestVerify(md.get(), der.data(), der.size(), PtrOrEmpty(message), message.size());
    return rc == 1 ? OkStatus() : Status(SG_INVALID_SIGNATURE);
}

SoftwareP256Key::~SoftwareP256Key() { EVP_PKEY_free(static_cast<EVP_PKEY*>(pkey_)); }

Status SoftwareP256Key::Generate(std::unique_ptr<SoftwareP256Key>* out)
{
    if (out == nullptr) return SG_INVALID_ARGUMENT;
    ErrorQueueGuard guard;
    char curve[] = "P-256";
    PkeyPtr pkey(EVP_PKEY_Q_keygen(nullptr, nullptr, "EC", curve));
    if (!pkey) return SG_CRYPTO_ERROR;
    SG_TRY(PrepareSoftwareKey(pkey.get()));
    out->reset(new SoftwareP256Key(pkey.release()));
    return OkStatus();
}

Status SoftwareP256Key::FromPkcs8Der(ByteView der, std::unique_ptr<SoftwareP256Key>* out)
{
    if (out == nullptr || der.empty() || !FitsInt(der.size())) return SG_INVALID_ARGUMENT;
    ErrorQueueGuard guard;
    const unsigned char* p = der.data();
    std::unique_ptr<PKCS8_PRIV_KEY_INFO, P8Deleter> p8(d2i_PKCS8_PRIV_KEY_INFO(nullptr, &p, static_cast<long>(der.size())));
    if (!p8 || p != der.data() + der.size()) return SG_INVALID_ARGUMENT;
    PkeyPtr pkey(EVP_PKCS82PKEY(p8.get()));
    if (!pkey) return SG_INVALID_ARGUMENT;
    SG_TRY(PrepareSoftwareKey(pkey.get()));
    out->reset(new SoftwareP256Key(pkey.release()));
    return OkStatus();
}

Status SoftwareP256Key::FromPem(ByteView pem, std::unique_ptr<SoftwareP256Key>* out)
{
    if (out == nullptr || pem.empty() || !FitsInt(pem.size())) return SG_INVALID_ARGUMENT;
    ErrorQueueGuard guard;
    std::unique_ptr<BIO, BioDeleter> bio(BIO_new_mem_buf(pem.data(), static_cast<int>(pem.size())));
    if (!bio) return SG_OUT_OF_MEMORY;
    PkeyPtr pkey(PEM_read_bio_PrivateKey(bio.get(), nullptr, &NoPasswordCallback, nullptr));
    if (!pkey) return SG_INVALID_ARGUMENT;
    SG_TRY(PrepareSoftwareKey(pkey.get()));
    out->reset(new SoftwareP256Key(pkey.release()));
    return OkStatus();
}

Status SoftwareP256Key::ToPkcs8Der(SecureBytes* out) const
{
    if (out == nullptr) return SG_INVALID_ARGUMENT;
    ErrorQueueGuard guard;
    std::unique_ptr<PKCS8_PRIV_KEY_INFO, P8Deleter> p8(EVP_PKEY2PKCS8(static_cast<EVP_PKEY*>(pkey_)));
    if (!p8) return SG_CRYPTO_ERROR;
    const int len = i2d_PKCS8_PRIV_KEY_INFO(p8.get(), nullptr);
    if (len <= 0) return SG_CRYPTO_ERROR;
    out->assign(static_cast<size_t>(len), 0);
    uint8_t* p = out->data();
    if (i2d_PKCS8_PRIV_KEY_INFO(p8.get(), &p) != len) {
        out->clear();
        return SG_CRYPTO_ERROR;
    }
    return OkStatus();
}

Status SoftwareP256Key::PublicKey(P256PublicKey* out) const
{
    if (out == nullptr) return SG_INVALID_ARGUMENT;
    ErrorQueueGuard guard;
    size_t len = 0;
    if (EVP_PKEY_get_octet_string_param(static_cast<EVP_PKEY*>(pkey_), OSSL_PKEY_PARAM_ENCODED_PUBLIC_KEY, out->data(),
                                        out->size(), &len) != 1 ||
        len != kP256PublicKeySize || (*out)[0] != 0x04) {
        return SG_CRYPTO_ERROR;
    }
    return OkStatus();
}

Status SoftwareP256Key::Sign(ByteView message, P256Signature* out) const
{
    if (out == nullptr) return SG_INVALID_ARGUMENT;
    ErrorQueueGuard guard;
    MdCtxPtr md(EVP_MD_CTX_new());
    if (!md) return SG_OUT_OF_MEMORY;
    if (EVP_DigestSignInit(md.get(), nullptr, EVP_sha256(), nullptr, static_cast<EVP_PKEY*>(pkey_)) != 1) {
        return SG_CRYPTO_ERROR;
    }
    size_t der_len = 0;
    if (EVP_DigestSign(md.get(), nullptr, &der_len, PtrOrEmpty(message), message.size()) != 1 || der_len == 0) {
        return SG_CRYPTO_ERROR;
    }
    Bytes der(der_len);
    if (EVP_DigestSign(md.get(), der.data(), &der_len, PtrOrEmpty(message), message.size()) != 1) {
        return SG_CRYPTO_ERROR;
    }
    der.resize(der_len);
    return EcdsaDerToP1363(der, out);
}

}  // namespace sg::crypto
