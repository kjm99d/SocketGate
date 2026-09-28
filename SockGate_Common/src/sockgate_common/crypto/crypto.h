#pragma once
/**
 * @file
 * @brief Cryptographic primitives used by SockGate.
 *
 * This header is the crypto provider seam (ICryptoProvider in the design): the implementation is selected at
 * build time (crypto/openssl_crypto.cpp). Only vetted constructions are exposed — SHA-256, HMAC-SHA256,
 * HKDF-SHA256, AES-256-GCM and ECDSA P-256 — and no raw block cipher or custom scheme.
 *
 * @note The OpenSSL implementation clears the calling thread's OpenSSL error queue when an entry point that used
 *       OpenSSL returns, so stale errors never leak into unrelated SSL_get_error() calls.
 */

#include "sockgate_common/core/bytes.h"
#include "sockgate_common/core/status.h"

#include <array>
#include <cstddef>
#include <cstdint>
#include <initializer_list>
#include <memory>

namespace sg::crypto {

constexpr size_t kSha256Size = 32;          ///< SHA-256 digest size in bytes.
constexpr size_t kAeadKeySize = 32;         ///< AES-256-GCM key size in bytes.
constexpr size_t kAeadNonceSize = 12;       ///< AES-256-GCM nonce (IV) size in bytes.
constexpr size_t kAeadTagSize = 16;         ///< AES-256-GCM authentication tag size in bytes.
constexpr size_t kP256PublicKeySize = 65;   ///< SEC1 uncompressed point 0x04 || X || Y
constexpr size_t kP256SignatureSize = 64;   ///< IEEE P1363 r || s
constexpr size_t kP256ScalarSize = 32;      ///< Size of one P-256 scalar (r or s) in bytes.

using Sha256Digest = std::array<uint8_t, kSha256Size>;          ///< SHA-256 or HMAC-SHA256 output.
using AeadKey = std::array<uint8_t, kAeadKeySize>;              ///< AES-256-GCM key.
using AeadNonce = std::array<uint8_t, kAeadNonceSize>;          ///< AES-256-GCM nonce.
using AeadTag = std::array<uint8_t, kAeadTagSize>;              ///< AES-256-GCM authentication tag.
using P256PublicKey = std::array<uint8_t, kP256PublicKeySize>;  ///< SEC1 uncompressed P-256 public key.
using P256Signature = std::array<uint8_t, kP256SignatureSize>;  ///< ECDSA P-256 signature, P1363 r || s.

/**
 * @brief Fills a buffer with cryptographically secure random bytes (OpenSSL DRBG seeded from the OS CSPRNG).
 * @param[out] out  Buffer to fill; may be null only when @p size is 0.
 * @param[in]  size Number of bytes.
 * @retval SG_OK               @p out holds @p size random bytes.
 * @retval SG_INVALID_ARGUMENT @p out is null and @p size is not 0.
 * @retval SG_CRYPTO_ERROR     The random generator failed.
 */
Status RandomBytes(uint8_t* out, size_t size);

/**
 * @brief Fills a fixed-size array with cryptographically secure random bytes (see RandomBytes()).
 * @tparam N Array size.
 * @param[out] out Array to fill; must not be null.
 * @retval SG_OK           @p out holds random bytes.
 * @retval SG_CRYPTO_ERROR The random generator failed.
 */
template <size_t N>
Status RandomArray(std::array<uint8_t, N>* out)
{
    return RandomBytes(out->data(), N);
}

// ---- Hashing ---------------------------------------------------------------

/**
 * @brief Computes SHA-256 of @p data.
 * @param[in]  data Input bytes.
 * @param[out] out  Digest.
 * @retval SG_OK               Success.
 * @retval SG_INVALID_ARGUMENT @p out is null.
 * @retval SG_CRYPTO_ERROR     The hash provider failed.
 */
Status Sha256(ByteView data, Sha256Digest* out);
/**
 * @brief Computes SHA-256 of the concatenation of @p parts (no framing between parts).
 * @param[in]  parts Input byte ranges, hashed in order.
 * @param[out] out   Digest.
 * @retval SG_OK               Success.
 * @retval SG_INVALID_ARGUMENT @p out is null.
 * @retval SG_CRYPTO_ERROR     The hash provider failed.
 */
Status Sha256(std::initializer_list<ByteView> parts, Sha256Digest* out);

/**
 * @brief Incremental SHA-256.
 *
 * Errors latch: after a failure every later Update*() and Final() returns the same code. After a successful
 * Final() the hasher is finished and further use returns SG_INVALID_STATE. A construction failure is reported by
 * the first call.
 *
 * @note Not synchronised: use one instance from one thread at a time. Not copyable.
 */
class Sha256Hasher {
public:
    /** @brief Starts a new SHA-256 computation; a failure is latched and reported by the first call. */
    Sha256Hasher();
    /** @brief Releases the hash context. */
    ~Sha256Hasher();
    Sha256Hasher(const Sha256Hasher&) = delete;
    Sha256Hasher& operator=(const Sha256Hasher&) = delete;

    /**
     * @brief Hashes @p data.
     * @param[in] data Input bytes (may be empty).
     * @retval SG_OK            Success.
     * @retval SG_CRYPTO_ERROR  The hash provider failed (now or earlier).
     * @retval SG_INVALID_STATE Final() has already succeeded.
     */
    Status Update(ByteView data);
    /**
     * @brief Hashes @p v as 2 big-endian bytes.
     * @param[in] v Value.
     * @return As Update().
     */
    Status UpdateU16(uint16_t v);
    /**
     * @brief Hashes @p v as 4 big-endian bytes.
     * @param[in] v Value.
     * @return As Update().
     */
    Status UpdateU32(uint32_t v);
    /**
     * @brief Length-prefixed (u32 big endian) update, used for transcript framing.
     *
     * Hashes the size of @p data as a u32 big-endian value, then @p data.
     *
     * @param[in] data Input bytes.
     * @retval SG_INVALID_ARGUMENT @p data is larger than 0xFFFFFFFF bytes (not latched; nothing is hashed).
     * @return Otherwise as Update().
     */
    Status UpdateWithLength(ByteView data);
    /**
     * @brief Writes the digest and finishes the hasher.
     * @param[out] out Digest.
     * @retval SG_OK               Success; the hasher can no longer be used.
     * @retval SG_INVALID_ARGUMENT @p out is null (not latched).
     * @retval SG_CRYPTO_ERROR     The hash provider failed (now or earlier).
     * @retval SG_INVALID_STATE    Final() has already succeeded.
     */
    Status Final(Sha256Digest* out);

private:
    struct Impl;
    std::unique_ptr<Impl> impl_;  ///< OpenSSL digest context.
    Status status_;               ///< Latched error; SG_INVALID_STATE once finalised.
};

// ---- MAC / KDF -------------------------------------------------------------

/**
 * @brief Computes HMAC-SHA256 over the concatenation of @p parts.
 * @param[in]  key   HMAC key (may be empty).
 * @param[in]  parts Message byte ranges, processed in order (no framing between parts).
 * @param[out] out   MAC.
 * @retval SG_OK               Success.
 * @retval SG_INVALID_ARGUMENT @p out is null.
 * @retval SG_CRYPTO_ERROR     The MAC provider failed.
 */
Status HmacSha256(ByteView key, std::initializer_list<ByteView> parts, Sha256Digest* out);

/**
 * @brief RFC 5869 HKDF with SHA-256 (extract and expand).
 *
 * An empty @p salt means HashLen zero bytes (RFC 5869 §2.2).
 *
 * @param[in]  ikm     Input keying material.
 * @param[in]  salt    Salt (may be empty).
 * @param[in]  info    Context information (may be empty).
 * @param[out] out     Output keying material.
 * @param[in]  out_len Number of bytes to derive; 1 .. 255 * 32.
 * @retval SG_OK               @p out holds @p out_len derived bytes.
 * @retval SG_INVALID_ARGUMENT @p out is null, or @p out_len is 0 or greater than 255 * 32.
 * @retval SG_CRYPTO_ERROR     Derivation failed; @p out is then wiped.
 */
Status HkdfSha256(ByteView ikm, ByteView salt, ByteView info, uint8_t* out, size_t out_len);

// ---- AEAD (AES-256-GCM) ----------------------------------------------------

/**
 * @brief Encrypts and authenticates with AES-256-GCM.
 *
 * @warning A nonce must never be reused with the same key.
 *
 * @param[in]  key            Key.
 * @param[in]  nonce          Nonce.
 * @param[in]  aad            Additional authenticated data (may be empty).
 * @param[in]  plaintext      Data to encrypt.
 * @param[out] ciphertext_out Must have room for plaintext.size() bytes (may alias nothing); may be null only when
 *                            @p plaintext is empty.
 * @param[out] tag_out        Authentication tag.
 * @retval SG_OK               Success.
 * @retval SG_INVALID_ARGUMENT A required output is null, or @p aad or @p plaintext is larger than INT_MAX bytes.
 * @retval SG_OUT_OF_MEMORY    The cipher context could not be allocated.
 * @retval SG_CRYPTO_ERROR     Encryption failed.
 */
Status AesGcmSeal(const AeadKey& key, const AeadNonce& nonce, ByteView aad, ByteView plaintext,
                  uint8_t* ciphertext_out, AeadTag* tag_out);

/**
 * @brief Decrypts and verifies AES-256-GCM.
 *
 * @param[in]  key           Key.
 * @param[in]  nonce         Nonce used for sealing.
 * @param[in]  aad           Additional authenticated data (may be empty).
 * @param[in]  ciphertext    Data to decrypt.
 * @param[in]  tag           Authentication tag.
 * @param[out] plaintext_out Must have room for ciphertext.size() bytes; may be null only when @p ciphertext is
 *                           empty.
 * @retval SG_OK               The tag is valid; @p plaintext_out holds the plaintext.
 * @retval SG_INVALID_ARGUMENT @p plaintext_out is null for a non-empty @p ciphertext, or @p aad or @p ciphertext
 *                             is larger than INT_MAX bytes.
 * @retval SG_OUT_OF_MEMORY    The cipher context could not be allocated.
 * @retval SG_CRYPTO_ERROR     Authentication fails (or decryption fails); plaintext_out is then wiped.
 */
Status AesGcmOpen(const AeadKey& key, const AeadNonce& nonce, ByteView aad, ByteView ciphertext,
                  const AeadTag& tag, uint8_t* plaintext_out);

// ---- ECDSA P-256 -------------------------------------------------------------

/**
 * @brief Validates a P-256 public key.
 *
 * Checks encoding (uncompressed, 65 bytes) and that the point is on the curve and not the point at infinity.
 *
 * @param[in] sec1 SEC1-encoded public key.
 * @retval SG_OK               The key is valid.
 * @retval SG_INVALID_ARGUMENT Wrong size or prefix, or the key could not be imported or failed the public-key
 *                             check. An internal OpenSSL failure (e.g. allocation) during import or check is
 *                             reported with this code too.
 * @retval SG_CRYPTO_ERROR     The key-import context could not be created or initialised.
 */
Status ValidateP256PublicKey(ByteView sec1);

/**
 * @brief Verifies an ECDSA-P256-SHA256 signature (P1363 r||s) over message.
 *
 * The public key is validated as by ValidateP256PublicKey() before use.
 *
 * @param[in] sec1_public_key SEC1 uncompressed public key (65 bytes).
 * @param[in] message         Signed message (hashed with SHA-256 here).
 * @param[in] signature       P1363 signature (64 bytes).
 * @retval SG_OK                The signature is valid.
 * @retval SG_INVALID_SIGNATURE Any verification failure, including a malformed key or signature (wrong size,
 *                              r or s zero). Any failure while validating the key or converting the signature,
 *                              and an error result from the verify call, are reported with this code too, even
 *                              when the cause is internal (e.g. allocation).
 * @retval SG_OUT_OF_MEMORY     The digest context could not be allocated.
 * @retval SG_CRYPTO_ERROR      The verifier could not be initialised.
 */
Status VerifyP256(ByteView sec1_public_key, ByteView message, ByteView signature);

/**
 * @brief Converts a DER ECDSA-Sig-Value to the fixed-size P1363 encoding.
 * @param[in]  der DER signature; the whole input must be consumed.
 * @param[out] out r || s, each left-padded to 32 bytes.
 * @retval SG_OK                Success.
 * @retval SG_INVALID_ARGUMENT  @p out is null, or @p der is empty or larger than INT_MAX bytes.
 * @retval SG_INVALID_SIGNATURE Malformed DER, trailing bytes, or r or s longer than 32 bytes.
 */
Status EcdsaDerToP1363(ByteView der, P256Signature* out);
/**
 * @brief Converts a fixed-size P1363 signature to a DER ECDSA-Sig-Value.
 * @param[in]  p1363   r || s (64 bytes).
 * @param[out] der_out DER signature (replaces the previous contents).
 * @retval SG_OK                Success.
 * @retval SG_INVALID_ARGUMENT  @p der_out is null or @p p1363 is not 64 bytes.
 * @retval SG_INVALID_SIGNATURE r or s is zero.
 * @retval SG_OUT_OF_MEMORY     The signature object could not be allocated.
 * @retval SG_CRYPTO_ERROR      DER encoding failed.
 */
Status EcdsaP1363ToDer(ByteView p1363, Bytes* der_out);

/**
 * @brief A P-256 private key held in process memory (OpenSSL EVP_PKEY).
 *
 * Used by the file/memory key stores and by the server proof key. Hardware-backed stores implement signing
 * without ever exposing an object like this. Created only through Generate(), FromPkcs8Der() or FromPem(), which
 * accept P-256 keys only.
 *
 * @note The const methods create their own OpenSSL context per call and do not modify the object; the server
 *       shares one const instance between threads. Not copyable.
 */
class SoftwareP256Key {
public:
    /** @brief Frees the key (EVP_PKEY_free()). */
    ~SoftwareP256Key();
    SoftwareP256Key(const SoftwareP256Key&) = delete;
    SoftwareP256Key& operator=(const SoftwareP256Key&) = delete;

    /**
     * @brief Generates a new random P-256 key.
     * @param[out] out Receives the key.
     * @retval SG_OK               Success.
     * @retval SG_INVALID_ARGUMENT @p out is null.
     * @retval SG_CRYPTO_ERROR     Key generation failed.
     */
    static Status Generate(std::unique_ptr<SoftwareP256Key>* out);
    /**
     * @brief Loads an unencrypted PKCS#8 DER private key.
     * @param[in]  der PKCS#8 PrivateKeyInfo; the whole input must be consumed.
     * @param[out] out Receives the key.
     * @retval SG_OK               Success.
     * @retval SG_INVALID_ARGUMENT @p out is null, @p der is empty, too large or malformed, has trailing bytes, or
     *                             is not a P-256 key.
     * @retval SG_CRYPTO_ERROR     The key could not be prepared.
     */
    static Status FromPkcs8Der(ByteView der, std::unique_ptr<SoftwareP256Key>* out);
    /**
     * @brief Loads a PEM private key; encrypted keys are rejected (no password prompt).
     * @param[in]  pem PEM text.
     * @param[out] out Receives the key.
     * @retval SG_OK               Success.
     * @retval SG_INVALID_ARGUMENT @p out is null, @p pem is empty, too large or unreadable (including encrypted), or
     *                             the key is not P-256.
     * @retval SG_OUT_OF_MEMORY    The memory BIO could not be allocated.
     * @retval SG_CRYPTO_ERROR     The key could not be prepared.
     */
    static Status FromPem(ByteView pem, std::unique_ptr<SoftwareP256Key>* out);

    /**
     * @brief Exports the private key as unencrypted PKCS#8 DER.
     * @warning The output is secret key material; it is held in SecureBytes so it is wiped on release.
     * @param[out] out Receives the DER on success (replacing the previous contents).
     * @retval SG_OK               Success.
     * @retval SG_INVALID_ARGUMENT @p out is null.
     * @retval SG_CRYPTO_ERROR     Encoding failed.
     */
    Status ToPkcs8Der(SecureBytes* out) const;
    /**
     * @brief Returns the public key as a SEC1 uncompressed point.
     * @param[out] out Public key.
     * @retval SG_OK               Success.
     * @retval SG_INVALID_ARGUMENT @p out is null.
     * @retval SG_CRYPTO_ERROR     The key could not be encoded as a 65-byte uncompressed point.
     */
    Status PublicKey(P256PublicKey* out) const;
    /**
     * @brief Signs @p message with ECDSA-P256-SHA256.
     * @param[in]  message Message (hashed with SHA-256 here).
     * @param[out] out     P1363 signature r || s.
     * @retval SG_OK               Success.
     * @retval SG_INVALID_ARGUMENT @p out is null.
     * @retval SG_OUT_OF_MEMORY    The digest context could not be allocated.
     * @retval SG_CRYPTO_ERROR     Signing failed.
     */
    Status Sign(ByteView message, P256Signature* out) const;

    /**
     * @brief Opaque EVP_PKEY* for TLS integration (not owned by the caller).
     * @return The key handle; valid for the lifetime of this object.
     */
    void* NativeHandle() const noexcept { return pkey_; }

private:
    /** @brief Takes ownership of an EVP_PKEY. @param[in] pkey EVP_PKEY*. */
    explicit SoftwareP256Key(void* pkey) noexcept : pkey_(pkey) {}
    void* pkey_;  ///< EVP_PKEY*
};

}  // namespace sg::crypto
