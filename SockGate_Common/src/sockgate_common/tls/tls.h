// TLS abstraction (ITlsProvider / ITlsContext / ITlsEngine).
//
// The engine is sans-IO: ciphertext is exchanged with the caller through
// FeedIncoming()/TakeOutgoing(), so the same implementation serves the
// blocking client transport, the IOCP/epoll server and in-memory tests, and
// it runs unchanged through HTTP CONNECT / SOCKS tunnels.
//
// Engines are not thread-safe; callers serialise access.
#pragma once

#include "sockgate_common/core/bytes.h"
#include "sockgate_common/core/status.h"
#include "sockgate_common/crypto/crypto.h"

#include <memory>
#include <string>
#include <vector>

namespace sg::tls {

struct TlsClientConfig {
    // Name used for certificate verification. DNS names are also sent as SNI;
    // IP literals are verified against iPAddress SANs.
    std::string server_name;

    // Trust anchors: any combination of a PEM file, in-memory PEM and the
    // operating system store. At least one source is required.
    std::string ca_file;
    std::string ca_pem;
    bool trust_system_store = false;

    // SHA-256 of DER SubjectPublicKeyInfo. When non-empty, at least one
    // certificate of the *verified* chain must match (checked after chain and
    // hostname validation succeeded).
    std::vector<crypto::Sha256Digest> spki_pins;

    // TLS 1.3 only unless explicitly enabled. TLS 1.2 additionally requires
    // the Extended Master Secret extension (RFC 9266 channel binding).
    bool allow_tls12 = false;
};

struct TlsServerConfig {
    std::string cert_chain_file;    // PEM: leaf first, then intermediates
    std::string cert_chain_pem;
    std::string private_key_file;   // PEM (unencrypted)
    SecureBytes private_key_pem;
    bool allow_tls12 = false;
};

struct TlsSessionInfo {
    std::string protocol;  // "TLSv1.3"
    std::string cipher;
    bool tls13 = false;
    bool extended_master_secret = false;
};

class ITlsEngine {
public:
    virtual ~ITlsEngine() = default;

    // Hands ciphertext received from the transport to the engine.
    virtual Status FeedIncoming(ByteView ciphertext) = 0;

    // Drives the handshake. OK when complete, kStatusWouldBlock when more
    // input is needed (flush TakeOutgoing() first), otherwise a terminal error:
    // SG_CERTIFICATE_ERROR, SG_PINNING_ERROR or SG_TLS_ERROR.
    virtual Status Handshake() = 0;
    virtual bool IsHandshakeComplete() const noexcept = 0;

    // Encrypts plaintext into the outgoing buffer.
    virtual Status Write(ByteView plaintext) = 0;

    // Decrypts buffered input. kStatusWouldBlock when no plaintext is
    // available, SG_CLOSED after the peer's close_notify.
    virtual Status Read(uint8_t* out, size_t capacity, size_t* read) = 0;

    virtual size_t PendingOutgoing() const noexcept = 0;
    // Appends pending ciphertext to *out.
    virtual void TakeOutgoing(Bytes* out) = 0;
    // Ciphertext fed but not yet consumed by the TLS state machine.
    virtual size_t BufferedIncoming() const noexcept = 0;

    // RFC 5705 / RFC 8446 exporter.
    virtual Status ExportKeyingMaterial(const std::string& label, ByteView context, bool use_context, uint8_t* out,
                                        size_t size) = 0;
    // RFC 9266 tls-exporter channel binding (32 bytes, no context).
    virtual Status ChannelBinding(crypto::Sha256Digest* out) = 0;

    // TLS 1.3 KeyUpdate (update_requested); no-op success on TLS 1.2.
    virtual Status RequestKeyUpdate() = 0;

    // Queues close_notify.
    virtual Status Shutdown() = 0;

    virtual TlsSessionInfo SessionInfo() const = 0;

    // Human-readable reason for the last failure (for logs; contains no secrets).
    virtual const std::string& ErrorDetail() const noexcept = 0;
};

class ITlsContext {
public:
    virtual ~ITlsContext() = default;
    virtual Status CreateEngine(std::unique_ptr<ITlsEngine>* out) = 0;
};

class ITlsProvider {
public:
    virtual ~ITlsProvider() = default;
    virtual Status CreateClientContext(const TlsClientConfig& config, std::shared_ptr<ITlsContext>* out) = 0;
    virtual Status CreateServerContext(const TlsServerConfig& config, std::shared_ptr<ITlsContext>* out) = 0;
};

// OpenSSL-backed provider (the only backend in v1).
ITlsProvider& DefaultTlsProvider();

// SHA-256 over the DER SubjectPublicKeyInfo of the first certificate in a PEM blob.
Status ComputeSpkiPinFromPem(ByteView certificate_pem, crypto::Sha256Digest* out);

// True for OpenSSL versions before upstream 3.0.7 (X.509 verification
// CVE-2022-3602/3786).
bool IsOutdatedOpenSsl(unsigned long version_num);

// The runtime OpenSSL version string if this build ships its own OpenSSL
// (Windows, or a static link) and that OpenSSL is outdated; nullptr
// otherwise. A system (distribution) OpenSSL is never reported: distributions
// backport security fixes without changing the version number, so the build
// warns about it at configure time instead (design 12 §1).
const char* OutdatedBundledOpenSslVersion();

}  // namespace sg::tls
