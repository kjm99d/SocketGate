// OpenSSL implementation of the TLS abstraction (memory-BIO, sans-IO engine).
#include "sockgate_common/tls/tls.h"

#include "sockgate_common/platform/trust_store.h"

#include <openssl/err.h>
#include <openssl/pem.h>
#include <openssl/ssl.h>
#include <openssl/x509.h>
#include <openssl/x509v3.h>

#include <climits>
#include <cstring>

namespace sg::tls {
namespace {

constexpr char kTls13CipherSuites[] =
    "TLS_AES_256_GCM_SHA384:TLS_CHACHA20_POLY1305_SHA256:TLS_AES_128_GCM_SHA256";
// Compatibility mode only: forward secret, AEAD-only suites.
constexpr char kTls12CipherList[] =
    "ECDHE-ECDSA-AES256-GCM-SHA384:ECDHE-RSA-AES256-GCM-SHA384:"
    "ECDHE-ECDSA-CHACHA20-POLY1305:ECDHE-RSA-CHACHA20-POLY1305:"
    "ECDHE-ECDSA-AES128-GCM-SHA256:ECDHE-RSA-AES128-GCM-SHA256";
constexpr char kChannelBindingLabel[] = "EXPORTER-Channel-Binding";

struct SslCtxDeleter { void operator()(SSL_CTX* p) const { SSL_CTX_free(p); } };
struct SslDeleter { void operator()(SSL* p) const { SSL_free(p); } };
struct X509Deleter { void operator()(X509* p) const { X509_free(p); } };
struct BioDeleter { void operator()(BIO* p) const { BIO_free(p); } };
struct PkeyDeleter { void operator()(EVP_PKEY* p) const { EVP_PKEY_free(p); } };
struct X509InfoStackDeleter {
    void operator()(STACK_OF(X509_INFO)* p) const { sk_X509_INFO_pop_free(p, X509_INFO_free); }
};
struct Asn1OctetDeleter { void operator()(ASN1_OCTET_STRING* p) const { ASN1_OCTET_STRING_free(p); } };

using SslCtxPtr = std::unique_ptr<SSL_CTX, SslCtxDeleter>;
using SslPtr = std::unique_ptr<SSL, SslDeleter>;
using X509Ptr = std::unique_ptr<X509, X509Deleter>;
using BioPtr = std::unique_ptr<BIO, BioDeleter>;

int NoPasswordCallback(char*, int, int, void*) { return 0; }

std::string LastOpenSslError()
{
    const unsigned long e = ERR_peek_last_error();
    if (e == 0) return "unknown";
    char buf[256];
    ERR_error_string_n(e, buf, sizeof(buf));
    return buf;
}

bool IsIpLiteral(const std::string& name)
{
    std::unique_ptr<ASN1_OCTET_STRING, Asn1OctetDeleter> ip(a2i_IPADDRESS(name.c_str()));
    ERR_clear_error();
    return ip != nullptr;
}

Status SpkiDigest(X509* cert, crypto::Sha256Digest* out)
{
    X509_PUBKEY* pub = X509_get_X509_PUBKEY(cert);
    if (pub == nullptr) return SG_CERTIFICATE_ERROR;
    const int len = i2d_X509_PUBKEY(pub, nullptr);
    if (len <= 0) return SG_CERTIFICATE_ERROR;
    Bytes der(static_cast<size_t>(len));
    uint8_t* p = der.data();
    if (i2d_X509_PUBKEY(pub, &p) != len) return SG_CERTIFICATE_ERROR;
    return crypto::Sha256(der, out);
}

Status ApplyCommonPolicy(SSL_CTX* ctx, bool allow_tls12)
{
    if (SSL_CTX_set_min_proto_version(ctx, allow_tls12 ? TLS1_2_VERSION : TLS1_3_VERSION) != 1 ||
        SSL_CTX_set_max_proto_version(ctx, TLS1_3_VERSION) != 1 ||
        SSL_CTX_set_ciphersuites(ctx, kTls13CipherSuites) != 1 ||
        SSL_CTX_set_cipher_list(ctx, kTls12CipherList) != 1) {
        return SG_TLS_ERROR;
    }
    SSL_CTX_set_options(ctx, SSL_OP_NO_COMPRESSION | SSL_OP_NO_RENEGOTIATION | SSL_OP_NO_TICKET);
    // No session resumption: every connection performs a full handshake and a
    // fresh SockGate authentication.
    SSL_CTX_set_session_cache_mode(ctx, SSL_SESS_CACHE_OFF);
    return OkStatus();
}

Status AddPemCertificates(X509_STORE* store, const std::string& pem, int* added)
{
    *added = 0;
    if (pem.size() > static_cast<size_t>(INT_MAX)) return SG_INVALID_ARGUMENT;
    BioPtr bio(BIO_new_mem_buf(pem.data(), static_cast<int>(pem.size())));
    if (!bio) return SG_OUT_OF_MEMORY;
    std::unique_ptr<STACK_OF(X509_INFO), X509InfoStackDeleter> infos(
        PEM_X509_INFO_read_bio(bio.get(), nullptr, &NoPasswordCallback, nullptr));
    if (!infos) return SG_CERTIFICATE_ERROR;
    for (int i = 0; i < sk_X509_INFO_num(infos.get()); ++i) {
        X509_INFO* info = sk_X509_INFO_value(infos.get(), i);
        if (info->x509 != nullptr && X509_STORE_add_cert(store, info->x509) == 1) ++*added;
    }
    ERR_clear_error();
    return *added > 0 ? OkStatus() : Status(SG_CERTIFICATE_ERROR);
}

struct ClientPolicy {
    std::string server_name;
    bool server_name_is_ip = false;
    std::vector<crypto::Sha256Digest> pins;
};

class OpenSslEngine final : public ITlsEngine {
public:
    OpenSslEngine(SslPtr ssl, bool client, ClientPolicy policy)
        : ssl_(std::move(ssl)), client_(client), policy_(std::move(policy))
    {
    }

    Status Init()
    {
        BIO* rbio = BIO_new(BIO_s_mem());
        BIO* wbio = BIO_new(BIO_s_mem());
        if (rbio == nullptr || wbio == nullptr) {
            BIO_free(rbio);
            BIO_free(wbio);
            return SG_OUT_OF_MEMORY;
        }
        // An empty read BIO means "retry later", not end-of-file.
        BIO_set_mem_eof_return(rbio, -1);
        SSL_set_bio(ssl_.get(), rbio, wbio);  // ownership moves to the SSL object
        rbio_ = rbio;
        wbio_ = wbio;

        if (!client_) {
            SSL_set_accept_state(ssl_.get());
            return OkStatus();
        }
        SSL_set_connect_state(ssl_.get());
        X509_VERIFY_PARAM* param = SSL_get0_param(ssl_.get());
        X509_VERIFY_PARAM_set_hostflags(param, X509_CHECK_FLAG_NO_PARTIAL_WILDCARDS);
        if (policy_.server_name_is_ip) {
            if (X509_VERIFY_PARAM_set1_ip_asc(param, policy_.server_name.c_str()) != 1) return SG_INVALID_ARGUMENT;
        } else {
            if (SSL_set1_host(ssl_.get(), policy_.server_name.c_str()) != 1 ||
                SSL_set_tlsext_host_name(ssl_.get(), policy_.server_name.c_str()) != 1) {
                return SG_INVALID_ARGUMENT;
            }
        }
        return OkStatus();
    }

    Status FeedIncoming(ByteView ciphertext) override
    {
        if (failed_) return last_error_;
        size_t offset = 0;
        while (offset < ciphertext.size()) {
            const size_t left = ciphertext.size() - offset;
            const int chunk = left > static_cast<size_t>(INT_MAX) ? INT_MAX : static_cast<int>(left);
            const int n = BIO_write(rbio_, ciphertext.data() + offset, chunk);
            if (n <= 0) return Fail(SG_OUT_OF_MEMORY, "BIO_write failed");
            offset += static_cast<size_t>(n);
        }
        return OkStatus();
    }

    Status Handshake() override
    {
        if (failed_) return last_error_;
        if (complete_) return OkStatus();
        ERR_clear_error();
        const int rc = SSL_do_handshake(ssl_.get());
        if (rc == 1) return PostHandshake();
        const int err = SSL_get_error(ssl_.get(), rc);
        if (err == SSL_ERROR_WANT_READ || err == SSL_ERROR_WANT_WRITE) return kStatusWouldBlock;

        const long verify = client_ ? SSL_get_verify_result(ssl_.get()) : X509_V_OK;
        if (verify != X509_V_OK) {
            return Fail(SG_CERTIFICATE_ERROR,
                        std::string("certificate verification failed: ") + X509_verify_cert_error_string(verify));
        }
        return Fail(SG_TLS_ERROR, "handshake failed: " + LastOpenSslError());
    }

    bool IsHandshakeComplete() const noexcept override { return complete_; }

    Status Write(ByteView plaintext) override
    {
        if (failed_) return last_error_;
        if (!complete_) return SG_INVALID_STATE;
        size_t offset = 0;
        while (offset < plaintext.size()) {
            ERR_clear_error();
            size_t written = 0;
            if (SSL_write_ex(ssl_.get(), plaintext.data() + offset, plaintext.size() - offset, &written) != 1 ||
                written == 0) {
                return Fail(SG_TLS_ERROR, "SSL_write failed: " + LastOpenSslError());
            }
            offset += written;
        }
        return OkStatus();
    }

    Status Read(uint8_t* out, size_t capacity, size_t* read) override
    {
        if (out == nullptr || capacity == 0 || read == nullptr) return SG_INVALID_ARGUMENT;
        *read = 0;
        if (failed_) return last_error_;
        if (!complete_) return SG_INVALID_STATE;
        if (peer_closed_) return SG_CLOSED;
        ERR_clear_error();
        size_t n = 0;
        if (SSL_read_ex(ssl_.get(), out, capacity, &n) == 1) {
            *read = n;
            return OkStatus();
        }
        const int err = SSL_get_error(ssl_.get(), 0);
        switch (err) {
        case SSL_ERROR_WANT_READ:
        case SSL_ERROR_WANT_WRITE:
            return kStatusWouldBlock;
        case SSL_ERROR_ZERO_RETURN:
            peer_closed_ = true;
            return SG_CLOSED;
        default:
            return Fail(SG_TLS_ERROR, "SSL_read failed: " + LastOpenSslError());
        }
    }

    size_t PendingOutgoing() const noexcept override { return BIO_ctrl_pending(wbio_); }

    void TakeOutgoing(Bytes* out) override
    {
        const size_t pending = BIO_ctrl_pending(wbio_);
        if (pending == 0 || out == nullptr) return;
        const size_t old = out->size();
        out->resize(old + pending);
        size_t got = 0;
        while (got < pending) {
            const size_t left = pending - got;
            const int chunk = left > static_cast<size_t>(INT_MAX) ? INT_MAX : static_cast<int>(left);
            const int n = BIO_read(wbio_, out->data() + old + got, chunk);
            if (n <= 0) break;
            got += static_cast<size_t>(n);
        }
        out->resize(old + got);
    }

    size_t BufferedIncoming() const noexcept override { return BIO_ctrl_pending(rbio_); }

    Status ExportKeyingMaterial(const std::string& label, ByteView context, bool use_context, uint8_t* out,
                                size_t size) override
    {
        if (out == nullptr || size == 0 || label.empty()) return SG_INVALID_ARGUMENT;
        if (!complete_ || failed_) return SG_INVALID_STATE;
        static const uint8_t kNoContext = 0;
        ERR_clear_error();
        const int rc = SSL_export_keying_material(ssl_.get(), out, size, label.c_str(), label.size(),
                                                  use_context ? (context.data() != nullptr ? context.data() : &kNoContext)
                                                              : nullptr,
                                                  use_context ? context.size() : 0, use_context ? 1 : 0);
        if (rc != 1) {
            SecureZero(out, size);
            return SG_TLS_ERROR;
        }
        return OkStatus();
    }

    Status ChannelBinding(crypto::Sha256Digest* out) override
    {
        if (out == nullptr) return SG_INVALID_ARGUMENT;
        return ExportKeyingMaterial(kChannelBindingLabel, ByteView(), false, out->data(), out->size());
    }

    Status RequestKeyUpdate() override
    {
        if (!complete_ || failed_) return SG_INVALID_STATE;
        if (SSL_version(ssl_.get()) != TLS1_3_VERSION) return OkStatus();
        ERR_clear_error();
        if (SSL_key_update(ssl_.get(), SSL_KEY_UPDATE_REQUESTED) != 1) return SG_TLS_ERROR;
        // Emit the KeyUpdate record into the outgoing buffer right away.
        const int rc = SSL_do_handshake(ssl_.get());
        if (rc != 1) {
            const int err = SSL_get_error(ssl_.get(), rc);
            if (err != SSL_ERROR_WANT_READ && err != SSL_ERROR_WANT_WRITE) return SG_TLS_ERROR;
        }
        return OkStatus();
    }

    Status Shutdown() override
    {
        if (!complete_) return OkStatus();
        ERR_clear_error();
        SSL_shutdown(ssl_.get());  // queues close_notify; completion is not awaited
        ERR_clear_error();
        return OkStatus();
    }

    TlsSessionInfo SessionInfo() const override
    {
        TlsSessionInfo info;
        info.protocol = SSL_get_version(ssl_.get());
        const SSL_CIPHER* cipher = SSL_get_current_cipher(ssl_.get());
        info.cipher = cipher != nullptr ? SSL_CIPHER_get_name(cipher) : "";
        info.tls13 = SSL_version(ssl_.get()) == TLS1_3_VERSION;
        info.extended_master_secret = SSL_get_extms_support(ssl_.get()) == 1;
        return info;
    }

    const std::string& ErrorDetail() const noexcept override { return error_detail_; }

private:
    Status Fail(Status status, std::string detail)
    {
        failed_ = true;
        last_error_ = status;
        error_detail_ = std::move(detail);
        ERR_clear_error();
        return status;
    }

    Status PostHandshake()
    {
        const int version = SSL_version(ssl_.get());
        if (version != TLS1_3_VERSION) {
            // RFC 9266: tls-exporter channel binding over TLS 1.2 requires EMS.
            if (version != TLS1_2_VERSION || SSL_get_extms_support(ssl_.get()) != 1) {
                return Fail(SG_TLS_ERROR, "TLS 1.2 without extended master secret");
            }
        }
        if (client_) {
            if (SSL_get_verify_result(ssl_.get()) != X509_V_OK) {
                return Fail(SG_CERTIFICATE_ERROR, "certificate verification failed");
            }
            X509* peer = SSL_get0_peer_certificate(ssl_.get());
            if (peer == nullptr) return Fail(SG_CERTIFICATE_ERROR, "no peer certificate");
            if (!policy_.pins.empty()) SG_TRY(CheckPins());
        }
        complete_ = true;
        return OkStatus();
    }

    // Pins are compared only against the chain OpenSSL *verified*, never
    // against the certificates the peer merely sent (CVE-2016-2402 pattern).
    Status CheckPins()
    {
        STACK_OF(X509)* chain = SSL_get0_verified_chain(ssl_.get());
        if (chain == nullptr) return Fail(SG_PINNING_ERROR, "no verified chain");
        for (int i = 0; i < sk_X509_num(chain); ++i) {
            crypto::Sha256Digest digest;
            if (!SpkiDigest(sk_X509_value(chain, i), &digest).ok()) continue;
            for (const auto& pin : policy_.pins) {
                if (ConstantTimeEqual(pin.data(), pin.size(), digest.data(), digest.size())) return OkStatus();
            }
        }
        // Diagnostic only: the issuer of an unexpected-but-trusted chain is the
        // typical fingerprint of TLS interception (corporate proxy, malware).
        std::string issuer = "?";
        if (sk_X509_num(chain) > 0) {
            char name[256] = {};
            X509_NAME_oneline(X509_get_issuer_name(sk_X509_value(chain, 0)), name, sizeof(name) - 1);
            issuer = name;
        }
        return Fail(SG_PINNING_ERROR,
                    "no certificate in the verified chain matches a configured SPKI pin (issuer: " + issuer +
                        "; possible TLS interception)");
    }

    SslPtr ssl_;
    const bool client_;
    const ClientPolicy policy_;
    BIO* rbio_ = nullptr;  // owned by ssl_
    BIO* wbio_ = nullptr;  // owned by ssl_
    bool complete_ = false;
    bool failed_ = false;
    bool peer_closed_ = false;
    Status last_error_ = OkStatus();
    std::string error_detail_;
};

class OpenSslContext final : public ITlsContext {
public:
    OpenSslContext(SslCtxPtr ctx, bool client, ClientPolicy policy)
        : ctx_(std::move(ctx)), client_(client), policy_(std::move(policy))
    {
    }

    Status CreateEngine(std::unique_ptr<ITlsEngine>* out) override
    {
        if (out == nullptr) return SG_INVALID_ARGUMENT;
        SslPtr ssl(SSL_new(ctx_.get()));
        if (!ssl) return SG_OUT_OF_MEMORY;
        auto engine = std::make_unique<OpenSslEngine>(std::move(ssl), client_, policy_);
        SG_TRY(engine->Init());
        *out = std::move(engine);
        return OkStatus();
    }

private:
    SslCtxPtr ctx_;
    const bool client_;
    const ClientPolicy policy_;
};

class OpenSslProvider final : public ITlsProvider {
public:
    Status CreateClientContext(const TlsClientConfig& config, std::shared_ptr<ITlsContext>* out) override
    {
        if (out == nullptr || config.server_name.empty() || config.server_name.size() > 253 ||
            config.server_name.find('\0') != std::string::npos) {
            return SG_INVALID_ARGUMENT;
        }
        ERR_clear_error();
        SslCtxPtr ctx(SSL_CTX_new(TLS_client_method()));
        if (!ctx) return SG_OUT_OF_MEMORY;
        SG_TRY(ApplyCommonPolicy(ctx.get(), config.allow_tls12));

        X509_STORE* store = SSL_CTX_get_cert_store(ctx.get());
        bool any_trust = false;
        if (!config.ca_file.empty()) {
            if (X509_STORE_load_file(store, config.ca_file.c_str()) != 1) {
                ERR_clear_error();
                return SG_CERTIFICATE_ERROR;
            }
            any_trust = true;
        }
        if (!config.ca_pem.empty()) {
            int added = 0;
            SG_TRY(AddPemCertificates(store, config.ca_pem, &added));
            any_trust = true;
        }
        if (config.trust_system_store) {
            SG_TRY(platform::AddSystemTrustAnchors(store));
            any_trust = true;
        }
        if (!any_trust) return SG_INVALID_ARGUMENT;
        SSL_CTX_set_verify(ctx.get(), SSL_VERIFY_PEER, nullptr);

        ClientPolicy policy;
        policy.server_name = config.server_name;
        policy.server_name_is_ip = IsIpLiteral(config.server_name);
        policy.pins = config.spki_pins;
        *out = std::make_shared<OpenSslContext>(std::move(ctx), true, std::move(policy));
        ERR_clear_error();
        return OkStatus();
    }

    Status CreateServerContext(const TlsServerConfig& config, std::shared_ptr<ITlsContext>* out) override
    {
        if (out == nullptr) return SG_INVALID_ARGUMENT;
        const bool has_chain = !config.cert_chain_file.empty() || !config.cert_chain_pem.empty();
        const bool has_key = !config.private_key_file.empty() || !config.private_key_pem.empty();
        if (!has_chain || !has_key) return SG_INVALID_ARGUMENT;

        ERR_clear_error();
        SslCtxPtr ctx(SSL_CTX_new(TLS_server_method()));
        if (!ctx) return SG_OUT_OF_MEMORY;
        SG_TRY(ApplyCommonPolicy(ctx.get(), config.allow_tls12));
        SSL_CTX_set_options(ctx.get(), SSL_OP_CIPHER_SERVER_PREFERENCE);
        SSL_CTX_set_num_tickets(ctx.get(), 0);
        SSL_CTX_set_default_passwd_cb(ctx.get(), &NoPasswordCallback);
        SSL_CTX_set_verify(ctx.get(), SSL_VERIFY_NONE, nullptr);  // clients authenticate at the SockGate layer

        Status st = LoadChain(ctx.get(), config);
        if (st.ok()) st = LoadKey(ctx.get(), config);
        if (st.ok() && SSL_CTX_check_private_key(ctx.get()) != 1) st = SG_INVALID_ARGUMENT;
        ERR_clear_error();
        SG_TRY(st);
        *out = std::make_shared<OpenSslContext>(std::move(ctx), false, ClientPolicy());
        return OkStatus();
    }

private:
    static Status LoadChain(SSL_CTX* ctx, const TlsServerConfig& config)
    {
        if (!config.cert_chain_file.empty()) {
            return SSL_CTX_use_certificate_chain_file(ctx, config.cert_chain_file.c_str()) == 1
                       ? OkStatus()
                       : Status(SG_CERTIFICATE_ERROR);
        }
        if (config.cert_chain_pem.size() > static_cast<size_t>(INT_MAX)) return SG_INVALID_ARGUMENT;
        BioPtr bio(BIO_new_mem_buf(config.cert_chain_pem.data(), static_cast<int>(config.cert_chain_pem.size())));
        if (!bio) return SG_OUT_OF_MEMORY;
        X509Ptr leaf(PEM_read_bio_X509_AUX(bio.get(), nullptr, &NoPasswordCallback, nullptr));
        if (!leaf || SSL_CTX_use_certificate(ctx, leaf.get()) != 1) return SG_CERTIFICATE_ERROR;
        for (;;) {
            X509* extra = PEM_read_bio_X509(bio.get(), nullptr, &NoPasswordCallback, nullptr);
            if (extra == nullptr) break;
            if (SSL_CTX_add0_chain_cert(ctx, extra) != 1) {
                X509_free(extra);
                return SG_CERTIFICATE_ERROR;
            }
        }
        ERR_clear_error();  // the loop always ends with a benign "no start line"
        return OkStatus();
    }

    static Status LoadKey(SSL_CTX* ctx, const TlsServerConfig& config)
    {
        if (!config.private_key_file.empty()) {
            return SSL_CTX_use_PrivateKey_file(ctx, config.private_key_file.c_str(), SSL_FILETYPE_PEM) == 1
                       ? OkStatus()
                       : Status(SG_INVALID_ARGUMENT);
        }
        if (config.private_key_pem.size() > static_cast<size_t>(INT_MAX)) return SG_INVALID_ARGUMENT;
        BioPtr bio(BIO_new_mem_buf(config.private_key_pem.data(), static_cast<int>(config.private_key_pem.size())));
        if (!bio) return SG_OUT_OF_MEMORY;
        std::unique_ptr<EVP_PKEY, PkeyDeleter> key(PEM_read_bio_PrivateKey(bio.get(), nullptr, &NoPasswordCallback, nullptr));
        if (!key || SSL_CTX_use_PrivateKey(ctx, key.get()) != 1) return SG_INVALID_ARGUMENT;
        return OkStatus();
    }
};

}  // namespace

ITlsProvider& DefaultTlsProvider()
{
    static OpenSslProvider provider;
    return provider;
}

Status ComputeSpkiPinFromPem(ByteView certificate_pem, crypto::Sha256Digest* out)
{
    if (out == nullptr || certificate_pem.empty() || certificate_pem.size() > static_cast<size_t>(INT_MAX)) {
        return SG_INVALID_ARGUMENT;
    }
    BioPtr bio(BIO_new_mem_buf(certificate_pem.data(), static_cast<int>(certificate_pem.size())));
    if (!bio) return SG_OUT_OF_MEMORY;
    X509Ptr cert(PEM_read_bio_X509(bio.get(), nullptr, &NoPasswordCallback, nullptr));
    ERR_clear_error();
    if (!cert) return SG_CERTIFICATE_ERROR;
    return SpkiDigest(cert.get(), out);
}

bool IsOutdatedOpenSsl(unsigned long version_num) { return version_num < 0x30000070UL; }

const char* OutdatedBundledOpenSslVersion()
{
#if defined(SOCKGATE_BUNDLED_OPENSSL) && SOCKGATE_BUNDLED_OPENSSL
    return IsOutdatedOpenSsl(OpenSSL_version_num()) ? OpenSSL_version(OPENSSL_VERSION) : nullptr;
#else
    return nullptr;
#endif
}

}  // namespace sg::tls
