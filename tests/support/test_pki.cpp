#include "support/test_pki.h"

#include <openssl/err.h>
#include <openssl/evp.h>
#include <openssl/pem.h>
#include <openssl/rand.h>
#include <openssl/x509.h>
#include <openssl/x509v3.h>

#include <stdexcept>

namespace sgtest {
namespace {

void Check(bool ok, const char* what)
{
    if (!ok) {
        ERR_print_errors_fp(stderr);
        throw std::runtime_error(std::string("test PKI: ") + what);
    }
}

std::shared_ptr<void> WrapCert(X509* x)
{
    return std::shared_ptr<void>(x, [](void* p) { X509_free(static_cast<X509*>(p)); });
}

std::shared_ptr<void> WrapKey(EVP_PKEY* k)
{
    return std::shared_ptr<void>(k, [](void* p) { EVP_PKEY_free(static_cast<EVP_PKEY*>(p)); });
}

void AddExt(X509* cert, X509* issuer, int nid, const std::string& value)
{
    X509V3_CTX ctx;
    X509V3_set_ctx_nodb(&ctx);
    X509V3_set_ctx(&ctx, issuer, cert, nullptr, nullptr, 0);
    X509_EXTENSION* ext = X509V3_EXT_conf_nid(nullptr, &ctx, nid, value.c_str());
    Check(ext != nullptr, "extension");
    Check(X509_add_ext(cert, ext, -1) == 1, "add extension");
    X509_EXTENSION_free(ext);
}

std::string ToPem(X509* cert)
{
    BIO* bio = BIO_new(BIO_s_mem());
    Check(bio && PEM_write_bio_X509(bio, cert) == 1, "cert pem");
    char* data = nullptr;
    const long len = BIO_get_mem_data(bio, &data);
    std::string out(data, static_cast<size_t>(len));
    BIO_free(bio);
    return out;
}

std::string ToPem(EVP_PKEY* key)
{
    BIO* bio = BIO_new(BIO_s_mem());
    Check(bio && PEM_write_bio_PrivateKey(bio, key, nullptr, nullptr, 0, nullptr, nullptr) == 1, "key pem");
    char* data = nullptr;
    const long len = BIO_get_mem_data(bio, &data);
    std::string out(data, static_cast<size_t>(len));
    BIO_free(bio);
    return out;
}

TestCert Build(const TestCert* issuer, const std::string& cn, const CertOptions& options)
{
    char curve[] = "P-256";
    EVP_PKEY* key = EVP_PKEY_Q_keygen(nullptr, nullptr, "EC", curve);
    Check(key != nullptr, "keygen");
    X509* cert = X509_new();
    Check(cert != nullptr, "X509_new");

    Check(X509_set_version(cert, 2) == 1, "version");
    uint64_t serial = 0;
    Check(RAND_bytes(reinterpret_cast<unsigned char*>(&serial), sizeof(serial)) == 1, "serial");
    serial &= 0x7FFFFFFFFFFFFFFFULL;
    Check(ASN1_INTEGER_set_int64(X509_get_serialNumber(cert), static_cast<int64_t>(serial | 1)) == 1, "serial set");
    Check(X509_gmtime_adj(X509_getm_notBefore(cert), static_cast<long>(options.not_before_offset_s)) != nullptr, "nb");
    Check(X509_gmtime_adj(X509_getm_notAfter(cert), static_cast<long>(options.not_after_offset_s)) != nullptr, "na");
    Check(X509_set_pubkey(cert, key) == 1, "pubkey");

    X509_NAME* name = X509_get_subject_name(cert);
    Check(X509_NAME_add_entry_by_txt(name, "CN", MBSTRING_ASC, reinterpret_cast<const unsigned char*>(cn.c_str()), -1,
                                     -1, 0) == 1,
          "cn");
    X509* issuer_cert = issuer != nullptr ? static_cast<X509*>(issuer->cert.get()) : cert;
    EVP_PKEY* issuer_key = issuer != nullptr ? static_cast<EVP_PKEY*>(issuer->key.get()) : key;
    Check(X509_set_issuer_name(cert, X509_get_subject_name(issuer_cert)) == 1, "issuer");

    AddExt(cert, issuer_cert, NID_subject_key_identifier, "hash");
    if (issuer != nullptr) AddExt(cert, issuer_cert, NID_authority_key_identifier, "keyid:always");
    if (options.is_ca) {
        AddExt(cert, issuer_cert, NID_basic_constraints, "critical,CA:TRUE");
        AddExt(cert, issuer_cert, NID_key_usage, "critical,keyCertSign,cRLSign");
    } else {
        AddExt(cert, issuer_cert, NID_basic_constraints, "critical,CA:FALSE");
        AddExt(cert, issuer_cert, NID_key_usage, "critical,digitalSignature");
        AddExt(cert, issuer_cert, NID_ext_key_usage, "serverAuth");
    }
    std::string san;
    for (const auto& d : options.dns_names) san += (san.empty() ? "" : ",") + std::string("DNS:") + d;
    for (const auto& ip : options.ip_addresses) san += (san.empty() ? "" : ",") + std::string("IP:") + ip;
    if (!san.empty()) AddExt(cert, issuer_cert, NID_subject_alt_name, san);

    Check(X509_sign(cert, issuer_key, EVP_sha256()) > 0, "sign");

    TestCert out;
    out.cert_pem = ToPem(cert);
    out.key_pem = ToPem(key);
    out.cert = WrapCert(cert);
    out.key = WrapKey(key);
    Check(sg::tls::ComputeSpkiPinFromPem(sg::ByteView(reinterpret_cast<const uint8_t*>(out.cert_pem.data()),
                                                      out.cert_pem.size()),
                                         &out.spki_sha256)
              .ok(),
          "spki");
    return out;
}

}  // namespace

TestCert CreateRootCa(const std::string& common_name)
{
    CertOptions o;
    o.is_ca = true;
    o.not_before_offset_s = -24 * 3600;
    o.not_after_offset_s = 30 * 24 * 3600;
    return Build(nullptr, common_name, o);
}

TestCert IssueCert(const TestCert& issuer, const std::string& common_name, const CertOptions& options)
{
    return Build(&issuer, common_name, options);
}

TestCert IssueLocalhostServer(const TestCert& issuer)
{
    CertOptions o;
    o.dns_names = {"localhost"};
    o.ip_addresses = {"127.0.0.1", "::1"};
    return Build(&issuer, "localhost", o);
}

sg::tls::TlsServerConfig ServerConfigFor(const TestCert& leaf, const std::string& extra_chain_pem)
{
    sg::tls::TlsServerConfig config;
    config.cert_chain_pem = leaf.cert_pem + extra_chain_pem;
    config.private_key_pem.assign(leaf.key_pem.begin(), leaf.key_pem.end());
    return config;
}

sg::tls::TlsClientConfig ClientConfigTrusting(const TestCert& ca, const std::string& server_name)
{
    sg::tls::TlsClientConfig config;
    config.server_name = server_name;
    config.ca_pem = ca.cert_pem;
    return config;
}

sg::Status Transfer(sg::tls::ITlsEngine& from, sg::tls::ITlsEngine& to)
{
    sg::Bytes buf;
    from.TakeOutgoing(&buf);
    if (buf.empty()) return sg::OkStatus();
    return to.FeedIncoming(buf);
}

sg::Status PumpHandshake(sg::tls::ITlsEngine& client, sg::tls::ITlsEngine& server, sg::Status* server_status)
{
    sg::Status cs = sg::kStatusWouldBlock;
    sg::Status ss = sg::kStatusWouldBlock;
    for (int round = 0; round < 32; ++round) {
        if (cs == sg::kStatusWouldBlock) cs = client.Handshake();
        (void)Transfer(client, server);
        if (ss == sg::kStatusWouldBlock) ss = server.Handshake();
        (void)Transfer(server, client);
        const bool client_done = cs != sg::kStatusWouldBlock;
        const bool server_done = ss != sg::kStatusWouldBlock;
        if (client_done && server_done) break;
        if ((client_done && !cs.ok()) || (server_done && !ss.ok())) {
            // Let the peer observe the alert, then stop.
            if (cs == sg::kStatusWouldBlock) cs = client.Handshake();
            if (ss == sg::kStatusWouldBlock) ss = server.Handshake();
            break;
        }
    }
    if (server_status != nullptr) *server_status = ss;
    return cs;
}

}  // namespace sgtest
