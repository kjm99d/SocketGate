// Runtime test PKI. Every key and certificate used by the tests is generated
// at run time: no private key material is ever committed to the repository.
#pragma once

#include "sockgate_common/crypto/crypto.h"
#include "sockgate_common/tls/tls.h"

#include <cstdint>
#include <memory>
#include <string>
#include <vector>

namespace sgtest {

struct TestCert {
    std::string cert_pem;
    std::string key_pem;
    sg::crypto::Sha256Digest spki_sha256{};
    std::shared_ptr<void> cert;  // X509*
    std::shared_ptr<void> key;   // EVP_PKEY*
};

struct CertOptions {
    std::vector<std::string> dns_names;
    std::vector<std::string> ip_addresses;
    int64_t not_before_offset_s = -3600;       // relative to now
    int64_t not_after_offset_s = 7 * 24 * 3600;
    bool is_ca = false;
};

TestCert CreateRootCa(const std::string& common_name);
TestCert IssueCert(const TestCert& issuer, const std::string& common_name, const CertOptions& options);
// Leaf for "localhost" / 127.0.0.1 / ::1 signed by issuer.
TestCert IssueLocalhostServer(const TestCert& issuer);

// Builds TLS configs for a server presenting `leaf` (+ optional extra chain PEM).
sg::tls::TlsServerConfig ServerConfigFor(const TestCert& leaf, const std::string& extra_chain_pem = "");
sg::tls::TlsClientConfig ClientConfigTrusting(const TestCert& ca, const std::string& server_name = "localhost");

// Pumps records between two in-memory engines until both finished the handshake
// or one of them failed. Returns the client status (server status via out param).
sg::Status PumpHandshake(sg::tls::ITlsEngine& client, sg::tls::ITlsEngine& server, sg::Status* server_status = nullptr);

// Moves all pending ciphertext from one engine to the other.
sg::Status Transfer(sg::tls::ITlsEngine& from, sg::tls::ITlsEngine& to);

}  // namespace sgtest
