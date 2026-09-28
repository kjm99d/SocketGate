// Cryptographic primitives used by SockGate.
//
// This header is the crypto provider seam (ICryptoProvider in the design):
// the implementation is selected at build time (crypto/openssl_crypto.cpp).
// Only vetted constructions are exposed — SHA-256, HMAC-SHA256, HKDF-SHA256,
// AES-256-GCM and ECDSA P-256 — and no raw block cipher or custom scheme.
#pragma once

#include "sockgate_common/core/bytes.h"
#include "sockgate_common/core/status.h"

#include <array>
#include <cstddef>
#include <cstdint>
#include <initializer_list>
#include <memory>

namespace sg::crypto {

constexpr size_t kSha256Size = 32;
constexpr size_t kAeadKeySize = 32;
constexpr size_t kAeadNonceSize = 12;
constexpr size_t kAeadTagSize = 16;
constexpr size_t kP256PublicKeySize = 65;   // SEC1 uncompressed point 0x04 || X || Y
constexpr size_t kP256SignatureSize = 64;   // IEEE P1363 r || s
constexpr size_t kP256ScalarSize = 32;

using Sha256Digest = std::array<uint8_t, kSha256Size>;
using AeadKey = std::array<uint8_t, kAeadKeySize>;
using AeadNonce = std::array<uint8_t, kAeadNonceSize>;
using AeadTag = std::array<uint8_t, kAeadTagSize>;
using P256PublicKey = std::array<uint8_t, kP256PublicKeySize>;
using P256Signature = std::array<uint8_t, kP256SignatureSize>;

// Cryptographically secure random bytes (OpenSSL DRBG seeded from the OS CSPRNG).
Status RandomBytes(uint8_t* out, size_t size);

template <size_t N>
Status RandomArray(std::array<uint8_t, N>* out)
{
    return RandomBytes(out->data(), N);
}

// ---- Hashing ---------------------------------------------------------------

Status Sha256(ByteView data, Sha256Digest* out);
Status Sha256(std::initializer_list<ByteView> parts, Sha256Digest* out);

class Sha256Hasher {
public:
    Sha256Hasher();
    ~Sha256Hasher();
    Sha256Hasher(const Sha256Hasher&) = delete;
    Sha256Hasher& operator=(const Sha256Hasher&) = delete;

    Status Update(ByteView data);
    Status UpdateU16(uint16_t v);
    Status UpdateU32(uint32_t v);
    // Length-prefixed (u32 big endian) update, used for transcript framing.
    Status UpdateWithLength(ByteView data);
    Status Final(Sha256Digest* out);

private:
    struct Impl;
    std::unique_ptr<Impl> impl_;
    Status status_;
};

// ---- MAC / KDF -------------------------------------------------------------

Status HmacSha256(ByteView key, std::initializer_list<ByteView> parts, Sha256Digest* out);

// RFC 5869 HKDF with SHA-256. out_len <= 255 * 32.
Status HkdfSha256(ByteView ikm, ByteView salt, ByteView info, uint8_t* out, size_t out_len);

// ---- AEAD (AES-256-GCM) ----------------------------------------------------

// ciphertext_out must have room for plaintext.size() bytes (may alias nothing).
Status AesGcmSeal(const AeadKey& key, const AeadNonce& nonce, ByteView aad, ByteView plaintext,
                  uint8_t* ciphertext_out, AeadTag* tag_out);

// Returns SG_CRYPTO_ERROR when authentication fails; plaintext_out is then
// wiped. plaintext_out must have room for ciphertext.size() bytes.
Status AesGcmOpen(const AeadKey& key, const AeadNonce& nonce, ByteView aad, ByteView ciphertext,
                  const AeadTag& tag, uint8_t* plaintext_out);

// ---- ECDSA P-256 -------------------------------------------------------------

// Checks encoding (uncompressed, 65 bytes) and that the point is on the curve
// and not the point at infinity.
Status ValidateP256PublicKey(ByteView sec1);

// Verifies an ECDSA-P256-SHA256 signature (P1363 r||s) over message.
// Returns SG_INVALID_SIGNATURE for any verification failure.
Status VerifyP256(ByteView sec1_public_key, ByteView message, ByteView signature);

// Converts between DER ECDSA-Sig-Value and fixed-size P1363 encodings.
Status EcdsaDerToP1363(ByteView der, P256Signature* out);
Status EcdsaP1363ToDer(ByteView p1363, Bytes* der_out);

// A P-256 private key held in process memory (OpenSSL EVP_PKEY). Used by the
// file/memory key stores and by the server proof key. Hardware-backed stores
// implement signing without ever exposing an object like this.
class SoftwareP256Key {
public:
    ~SoftwareP256Key();
    SoftwareP256Key(const SoftwareP256Key&) = delete;
    SoftwareP256Key& operator=(const SoftwareP256Key&) = delete;

    static Status Generate(std::unique_ptr<SoftwareP256Key>* out);
    static Status FromPkcs8Der(ByteView der, std::unique_ptr<SoftwareP256Key>* out);
    static Status FromPem(ByteView pem, std::unique_ptr<SoftwareP256Key>* out);

    Status ToPkcs8Der(SecureBytes* out) const;
    Status PublicKey(P256PublicKey* out) const;
    Status Sign(ByteView message, P256Signature* out) const;

    // Opaque EVP_PKEY* for TLS integration (not owned by the caller).
    void* NativeHandle() const noexcept { return pkey_; }

private:
    explicit SoftwareP256Key(void* pkey) noexcept : pkey_(pkey) {}
    void* pkey_;  // EVP_PKEY*
};

}  // namespace sg::crypto
