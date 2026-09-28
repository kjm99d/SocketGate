#pragma once
/**
 * @file
 * @brief TLS abstraction (ITlsProvider / ITlsContext / ITlsEngine).
 *
 * The engine is sans-IO: ciphertext is exchanged with the caller through
 * FeedIncoming()/TakeOutgoing(), so the same implementation serves the
 * blocking client transport, the IOCP/epoll server and in-memory tests, and
 * it runs unchanged through HTTP CONNECT / SOCKS tunnels.
 *
 * Engines are not thread-safe; callers serialise access.
 *
 * Policy of the OpenSSL backend (both roles): TLS 1.3 only unless allow_tls12 (then TLS 1.2 with forward-secret
 * AEAD suites only, and only with Extended Master Secret); no compression, renegotiation, session tickets or
 * session resumption, so every connection performs a full handshake.
 */

#include "sockgate_common/core/bytes.h"
#include "sockgate_common/core/status.h"
#include "sockgate_common/crypto/crypto.h"

#include <memory>
#include <string>
#include <vector>

/** @brief TLS abstraction and its OpenSSL backend. */
namespace sg::tls {

/** @brief Client-side TLS configuration for CreateClientContext() (not referenced after the call). */
struct TlsClientConfig {
    /**
     * Name used for certificate verification. DNS names are also sent as SNI;
     * IP literals are verified against iPAddress SANs. Required, at most 253 characters, no NUL. Partial
     * wildcards in certificate names (such as f*.example.com) are not matched.
     */
    std::string server_name;

    /**
     * @name Trust anchors
     * Trust anchors: any combination of a PEM file, in-memory PEM and the
     * operating system store. At least one source is required.
     * @{
     */
    std::string ca_file;  ///< Path of a PEM file of trust anchors; empty = not used.
    std::string ca_pem;   ///< In-memory PEM trust anchors; must contain at least one certificate when set.
    bool trust_system_store = false;  ///< Also trust the operating system root store.
    /** @} */

    /**
     * SHA-256 of DER SubjectPublicKeyInfo. When non-empty, at least one
     * certificate of the *verified* chain must match (checked after chain and
     * hostname validation succeeded).
     */
    std::vector<crypto::Sha256Digest> spki_pins;

    /**
     * TLS 1.3 only unless explicitly enabled. TLS 1.2 additionally requires
     * the Extended Master Secret extension (RFC 9266 channel binding).
     */
    bool allow_tls12 = false;
};

/**
 * @brief Server-side TLS configuration.
 *
 * A certificate chain and a private key are both required; a file path takes precedence over the in-memory
 * PEM of the same item. The server does not request client certificates (clients authenticate at the SockGate
 * layer).
 */
struct TlsServerConfig {
    std::string cert_chain_file;    ///< PEM: leaf first, then intermediates
    std::string cert_chain_pem;     ///< In-memory PEM chain: leaf first, then intermediates.
    std::string private_key_file;   ///< PEM (unencrypted)
    SecureBytes private_key_pem;    ///< In-memory PEM private key (unencrypted); wiped on deallocation.
    bool allow_tls12 = false;       ///< Also accept TLS 1.2 (with Extended Master Secret only).
};

/** @brief Negotiated parameters of a completed handshake. */
struct TlsSessionInfo {
    std::string protocol;  ///< e.g. "TLSv1.3"
    std::string cipher;    ///< Cipher suite name; empty when none is negotiated.
    bool tls13 = false;    ///< TLS 1.3 was negotiated.
    bool extended_master_secret = false;  ///< Extended Master Secret was negotiated.
};

/**
 * @brief One TLS connection (sans-IO).
 *
 * The caller moves ciphertext between the transport and the engine: FeedIncoming() for received bytes,
 * TakeOutgoing() for bytes to send. A failure reported as terminal latches: every later FeedIncoming(),
 * Handshake(), Write() and Read() returns the same status.
 *
 * @note Not thread-safe; callers serialise access.
 */
class ITlsEngine {
public:
    virtual ~ITlsEngine() = default;  ///< Releases the connection state.

    /**
     * @brief Hands ciphertext received from the transport to the engine.
     * @param[in] ciphertext Received bytes (copied).
     * @retval OK               Buffered.
     * @retval SG_OUT_OF_MEMORY Buffering failed (terminal).
     * @return The latched error once the engine has failed.
     */
    virtual Status FeedIncoming(ByteView ciphertext) = 0;

    /**
     * @brief Drives the handshake.
     *
     * OK when complete, kStatusWouldBlock when more
     * input is needed (flush TakeOutgoing() first), otherwise a terminal error:
     * SG_CERTIFICATE_ERROR, SG_PINNING_ERROR or SG_TLS_ERROR.
     * On completion the client has verified the chain and the host name / IP (and the SPKI pins when
     * configured); a TLS 1.2 session without Extended Master Secret is rejected with SG_TLS_ERROR.
     *
     * @retval OK                   Handshake complete (also on later calls).
     * @retval kStatusWouldBlock    More input needed.
     * @retval SG_CERTIFICATE_ERROR Chain or host name verification failed (client).
     * @retval SG_PINNING_ERROR     No certificate of the verified chain matches a pin (client).
     * @retval SG_TLS_ERROR         Any other handshake failure.
     */
    virtual Status Handshake() = 0;
    /** @brief Handshake state. @return True once Handshake() returned OK. */
    virtual bool IsHandshakeComplete() const noexcept = 0;

    /**
     * @brief Encrypts plaintext into the outgoing buffer.
     * @param[in] plaintext Bytes to send; all of them are consumed on success.
     * @retval OK               Encrypted; collect with TakeOutgoing().
     * @retval SG_INVALID_STATE Handshake not complete.
     * @retval SG_TLS_ERROR     Encryption failed (terminal).
     * @return The latched error once the engine has failed.
     */
    virtual Status Write(ByteView plaintext) = 0;

    /**
     * @brief Decrypts buffered input.
     *
     * kStatusWouldBlock when no plaintext is
     * available, SG_CLOSED after the peer's close_notify.
     *
     * @param[out] out      Destination buffer.
     * @param[in]  capacity Size of @p out in bytes; must not be 0.
     * @param[out] read     Number of bytes written to @p out; set to 0 on every result except OK and
     *                      SG_INVALID_ARGUMENT (then left untouched).
     * @retval OK                  At least one byte read.
     * @retval kStatusWouldBlock   No plaintext available yet.
     * @retval SG_CLOSED           The peer sent close_notify (also on every later call).
     * @retval SG_INVALID_ARGUMENT @p out or @p read is nullptr, or @p capacity is 0.
     * @retval SG_INVALID_STATE    Handshake not complete.
     * @retval SG_TLS_ERROR        Decryption or protocol failure (terminal).
     * @return The latched error once the engine has failed.
     */
    virtual Status Read(uint8_t* out, size_t capacity, size_t* read) = 0;

    /** @brief Outgoing backlog. @return Ciphertext bytes waiting to be collected with TakeOutgoing(). */
    virtual size_t PendingOutgoing() const noexcept = 0;
    /**
     * @brief Appends pending ciphertext to *out.
     * @param[in,out] out Buffer the pending ciphertext is appended to; nullptr does nothing.
     */
    virtual void TakeOutgoing(Bytes* out) = 0;
    /**
     * @brief Ciphertext fed but not yet consumed by the TLS state machine.
     * @return Number of such bytes.
     */
    virtual size_t BufferedIncoming() const noexcept = 0;

    /**
     * @brief RFC 5705 / RFC 8446 exporter.
     * @param[in]  label       Exporter label; must not be empty.
     * @param[in]  context     Context; used only when @p use_context is true (may then be empty, which is a
     *                         zero-length context, distinct from no context under TLS 1.2).
     * @param[in]  use_context Whether a context is supplied.
     * @param[out] out         Destination.
     * @param[in]  size        Number of bytes to export; must not be 0.
     * @retval OK                  Exported.
     * @retval SG_INVALID_ARGUMENT @p out is nullptr, @p size is 0 or @p label is empty.
     * @retval SG_INVALID_STATE    Handshake not complete, or the engine has failed.
     * @retval SG_TLS_ERROR        Export failed; @p out is wiped.
     * @warning The output is secret key material; the caller wipes it after use.
     */
    virtual Status ExportKeyingMaterial(const std::string& label, ByteView context, bool use_context, uint8_t* out,
                                        size_t size) = 0;
    /**
     * @brief RFC 9266 tls-exporter channel binding (32 bytes, zero-length context).
     *
     * Label "EXPORTER-Channel-Binding" with a zero-length context (use_context = 1), not "no context": the two
     * differ under TLS 1.2. Each peer computes it over its own TLS connection, so a man in the middle that
     * terminates TLS twice produces different values on the two sides.
     *
     * @param[out] out Receives the 32-byte value.
     * @retval OK                  Computed.
     * @retval SG_INVALID_ARGUMENT @p out is nullptr.
     * @retval SG_INVALID_STATE    Handshake not complete, or the engine has failed.
     * @retval SG_TLS_ERROR        Export failed.
     */
    virtual Status ChannelBinding(crypto::Sha256Digest* out) = 0;

    /**
     * @brief TLS 1.3 KeyUpdate (update_requested); no-op success on TLS 1.2.
     *
     * The KeyUpdate record is queued for TakeOutgoing() right away.
     *
     * @retval OK               KeyUpdate queued (or TLS 1.2).
     * @retval SG_INVALID_STATE Handshake not complete, or the engine has failed.
     * @retval SG_TLS_ERROR     KeyUpdate failed.
     */
    virtual Status RequestKeyUpdate() = 0;

    /**
     * @brief Queues close_notify.
     *
     * Completion is not awaited. Does nothing before the handshake has completed.
     *
     * @retval OK Always.
     */
    virtual Status Shutdown() = 0;

    /**
     * @brief Negotiated protocol, cipher and extensions.
     * @return Session parameters (meaningful after the handshake).
     */
    virtual TlsSessionInfo SessionInfo() const = 0;

    /**
     * @brief Human-readable reason for the last failure (for logs; contains no secrets).
     * @return Empty when no terminal failure has been recorded. The reference stays valid while the engine
     *         lives; a later failure overwrites the text.
     */
    virtual const std::string& ErrorDetail() const noexcept = 0;
};

/**
 * @brief Configured TLS context (trust anchors, certificate, policy) that creates engines.
 *
 * Each engine it creates is an independent connection object in the context's role.
 */
class ITlsContext {
public:
    virtual ~ITlsContext() = default;  ///< Releases the context.
    /**
     * @brief Creates a new engine in the client or server role of this context.
     * @param[out] out Receives the engine.
     * @retval OK                  Created.
     * @retval SG_INVALID_ARGUMENT @p out is nullptr, or the server name could not be applied (client).
     * @retval SG_OUT_OF_MEMORY    Allocation failed.
     */
    virtual Status CreateEngine(std::unique_ptr<ITlsEngine>* out) = 0;
};

/** @brief Factory of TLS contexts for one backend. */
class ITlsProvider {
public:
    virtual ~ITlsProvider() = default;  ///< Virtual destructor.
    /**
     * @brief Creates a client context.
     * @param[in]  config Client configuration (copied).
     * @param[out] out    Receives the context.
     * @retval OK                   Created.
     * @retval SG_INVALID_ARGUMENT  @p out is nullptr, server_name empty / longer than 253 / containing NUL, or
     *                              no trust source configured.
     * @retval SG_CERTIFICATE_ERROR ca_file cannot be loaded, or ca_pem contains no usable certificate.
     * @retval SG_TLS_ERROR         The protocol / cipher policy could not be applied.
     * @retval SG_OUT_OF_MEMORY     Allocation failed.
     * @return Otherwise the error from loading the system trust store.
     */
    virtual Status CreateClientContext(const TlsClientConfig& config, std::shared_ptr<ITlsContext>* out) = 0;
    /**
     * @brief Creates a server context.
     * @param[in]  config Server configuration (read during the call).
     * @param[out] out    Receives the context.
     * @retval OK                   Created.
     * @retval SG_INVALID_ARGUMENT  @p out is nullptr, chain or key missing, the key cannot be loaded, or the key
     *                              does not match the certificate.
     * @retval SG_CERTIFICATE_ERROR The certificate chain cannot be loaded.
     * @retval SG_TLS_ERROR         The protocol / cipher policy could not be applied.
     * @retval SG_OUT_OF_MEMORY     Allocation failed.
     */
    virtual Status CreateServerContext(const TlsServerConfig& config, std::shared_ptr<ITlsContext>* out) = 0;
};

/**
 * @brief OpenSSL-backed provider (the only backend in v1).
 * @return Process-wide instance; never destroyed before exit.
 */
ITlsProvider& DefaultTlsProvider();

/**
 * @brief SHA-256 over the DER SubjectPublicKeyInfo of the first certificate in a PEM blob.
 *
 * The result is a value for TlsClientConfig::spki_pins.
 *
 * @param[in]  certificate_pem PEM text; must not be empty.
 * @param[out] out             Receives the pin.
 * @retval OK                   Computed.
 * @retval SG_INVALID_ARGUMENT  @p out is nullptr, or @p certificate_pem is empty or too large.
 * @retval SG_CERTIFICATE_ERROR No certificate could be read, or its public key cannot be encoded.
 * @retval SG_OUT_OF_MEMORY     Allocation failed.
 * @return Otherwise the hash error.
 */
Status ComputeSpkiPinFromPem(ByteView certificate_pem, crypto::Sha256Digest* out);

/**
 * @brief True for OpenSSL versions before upstream 3.0.7 (X.509 verification
 * CVE-2022-3602/3786).
 * @param[in] version_num OpenSSL version number (OPENSSL_VERSION_NUMBER format).
 * @return true when @p version_num is below 0x30000070.
 */
bool IsOutdatedOpenSsl(unsigned long version_num);

/**
 * @brief Reports an outdated bundled OpenSSL.
 *
 * The runtime OpenSSL version string if this build ships its own OpenSSL
 * (Windows, or a static link) and that OpenSSL is outdated; nullptr
 * otherwise. A system (distribution) OpenSSL is never reported: distributions
 * backport security fixes without changing the version number, so the build
 * warns about it at configure time instead (design 12 §1).
 *
 * @return Static version string, or nullptr.
 */
const char* OutdatedBundledOpenSslVersion();

}  // namespace sg::tls
