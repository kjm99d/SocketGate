// sg_admin: offline administration of SockGate server state.
//
// The registry and license files are single-process stores: the server
// locks them while it runs, so edit them only while it is stopped (or use
// the server's C API from within the application).
//
//   sg_admin pin <cert.pem>
//   sg_admin token-key <file> [--force yes]
//   sg_admin token issue --key FILE --product P [--license L [--licenses FILE]] [--ttl-ms N]
//   sg_admin license add --store FILE --id L --product P [--features N] [--expires-ms N] [--seats N]
//   sg_admin license revoke|show --store FILE --id L
//   sg_admin client register --registry FILE --pubkey HEX [--product P] [--license L [--licenses FILE]]
//   sg_admin client revoke --registry FILE --iid HEX
//   sg_admin client list --registry FILE
//   sg_admin dev-pki <dir> [--host NAME] [--force yes]     (development only)
#include "storage/atomic_file.h"
#include "storage/client_registry.h"
#include "storage/license_store.h"

#include "sockgate_common/core/clock.h"
#include "sockgate_common/crypto/crypto.h"
#include "sockgate_common/protocol/enrollment_token.h"
#include "sockgate_common/protocol/transcript.h"
#include "sockgate_common/serialization/writer.h"
#include "sockgate_common/tls/tls.h"

#include <openssl/bn.h>
#include <openssl/evp.h>
#include <openssl/pem.h>
#include <openssl/x509.h>
#include <openssl/x509v3.h>

#include <cctype>
#include <cerrno>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <filesystem>
#include <map>
#include <memory>
#include <set>
#include <string>
#include <vector>

using namespace sg;
using namespace sg::server;

namespace {

int Fail(const std::string& message)
{
    std::fprintf(stderr, "sg_admin: %s\n", message.c_str());
    return 1;
}

int FailStatus(const char* what, Status st) { return Fail(std::string(what) + ": " + st.name()); }

// Opening a registry / license store: SG_INVALID_STATE means another process
// holds the store's lock (see LockStore).
int FailOpen(const char* what, Status st)
{
    if (st == SG_INVALID_STATE) {
        return Fail(std::string(what) + ": the store is in use (stop the server that uses it first)");
    }
    return FailStatus(what, st);
}

// "--name value" pairs after the command words; only the listed options are
// accepted, so a typo can never silently fall back to a default.
struct Args {
    std::map<std::string, std::string> values;
    std::string error;

    bool has(const std::string& name) const { return values.count(name) != 0; }
    std::string get(const std::string& name, const std::string& fallback = "") const
    {
        auto it = values.find(name);
        return it == values.end() ? fallback : it->second;
    }
};

Args ParseArgs(int argc, char** argv, int first, const std::set<std::string>& allowed)
{
    Args args;
    for (int i = first; i < argc; i += 2) {
        if (std::strncmp(argv[i], "--", 2) != 0 || i + 1 >= argc) {
            args.error = std::string("expected --option value at '") + argv[i] + "'";
            break;
        }
        const std::string name = argv[i] + 2;
        if (allowed.count(name) == 0) {
            args.error = "unknown option --" + name;
            break;
        }
        if (args.values.count(name) != 0) {
            args.error = "option --" + name + " given twice";
            break;
        }
        args.values[name] = argv[i + 1];
    }
    return args;
}

// Decimal, or hexadecimal with an explicit 0x prefix. No sign, whitespace,
// octal or overflow.
bool ParseU64(const std::string& text, uint64_t* out)
{
    const bool hex = text.size() > 2 && text[0] == '0' && (text[1] == 'x' || text[1] == 'X');
    const std::string digits = hex ? text.substr(2) : text;
    if (digits.empty() || digits.size() > (hex ? 16u : 20u)) return false;
    for (char c : digits) {
        const bool ok = hex ? std::isxdigit(static_cast<unsigned char>(c)) != 0 : (c >= '0' && c <= '9');
        if (!ok) return false;
    }
    errno = 0;
    char* end = nullptr;
    const unsigned long long value = std::strtoull(digits.c_str(), &end, hex ? 16 : 10);
    if (errno == ERANGE || end == nullptr || *end != '\0') return false;
    *out = value;
    return true;
}

bool ParseHex(const std::string& text, uint8_t* out, size_t size)
{
    if (text.size() != size * 2) return false;
    auto digit = [](char c) -> int {
        if (c >= '0' && c <= '9') return c - '0';
        if (c >= 'a' && c <= 'f') return c - 'a' + 10;
        if (c >= 'A' && c <= 'F') return c - 'A' + 10;
        return -1;
    };
    for (size_t i = 0; i < size; ++i) {
        const int hi = digit(text[2 * i]);
        const int lo = digit(text[2 * i + 1]);
        if (hi < 0 || lo < 0) return false;
        out[i] = static_cast<uint8_t>(hi * 16 + lo);
    }
    return true;
}

bool Exists(const std::string& path)
{
    std::error_code ec;
    return std::filesystem::exists(std::filesystem::u8path(path), ec);
}

// Refuses to replace an existing file unless --force yes was given.
bool MayWrite(const std::string& path, const Args& a)
{
    if (!Exists(path) || a.get("force") == "yes") return true;
    std::fprintf(stderr, "sg_admin: %s exists; pass --force yes to replace it\n", path.c_str());
    return false;
}

// Zeroes a byte buffer on every exit path.
struct Wipe {
    Bytes& bytes;
    ~Wipe() { SecureZero(bytes.data(), bytes.size()); }
};

// With --licenses, the check the server applies to registrations and tokens:
// a bound license must exist in the store, be active and be for the product.
// (Without it the license id is taken as given, like a server that does not
// set require_license.)
int CheckBinding(const Args& a)
{
    if (!a.has("license")) return a.has("licenses") ? Fail("--licenses needs --license") : 0;
    if (!a.has("licenses")) return 0;
    std::unique_ptr<ILicenseStore> store;
    Status st = CreateFileLicenseStore(a.get("licenses"), &store);
    if (!st.ok()) return FailOpen("open license store", st);
    LicenseRecord license;
    st = store->Find(a.get("license"), &license);
    if (!st.ok()) return FailStatus("find license", st);
    if (license.status != LicenseStatus::kActive) return Fail("license is revoked");
    if (a.has("product") && license.product_id != a.get("product")) return Fail("license is for another product");
    return 0;
}

// ---- pin / token key / token ----------------------------------------------------------

int CmdPin(const std::string& path)
{
    Bytes pem;
    const Status read = ReadWholeFile(path, &pem);
    if (!read.ok()) return FailStatus("read certificate", read);
    crypto::Sha256Digest pin;
    const Status st = tls::ComputeSpkiPinFromPem(pem, &pin);
    if (!st.ok()) return FailStatus("SPKI pin", st);
    std::printf("%s\n", ToHex(pin).c_str());
    return 0;
}

int CmdTokenKey(const std::string& path, const Args& a)
{
    if (!MayWrite(path, a)) return 1;  // replacing the key invalidates every issued token
    SecureBytes key(32);
    Status st = crypto::RandomBytes(key.data(), key.size());
    if (st.ok()) st = WriteFileAtomically(path, key);
    if (!st.ok()) return FailStatus("write token key", st);
    std::printf("wrote a 32-byte token key to %s (keep it secret: it authorises enrollments)\n", path.c_str());
    return 0;
}

int CmdTokenIssue(const Args& a)
{
    if (!a.has("key") || !a.has("product")) return Fail("token issue needs --key and --product");
    if (const int rc = CheckBinding(a)) return rc;
    uint64_t ttl = 24ull * 3600 * 1000;
    if (a.has("ttl-ms") && !ParseU64(a.get("ttl-ms"), &ttl)) return Fail("bad --ttl-ms");
    if (ttl == 0 || ttl > proto::kMaxEnrollmentTokenLifetimeMs) {
        return Fail("--ttl-ms must be between 1 and " + std::to_string(proto::kMaxEnrollmentTokenLifetimeMs) +
                    " (30 days)");
    }
    Bytes key;
    Wipe wipe_key{key};
    Status st = ReadWholeFile(a.get("key"), &key);
    if (!st.ok()) return FailStatus("read token key", st);
    if (key.size() < 32) return Fail("token key must be at least 32 bytes");
    proto::EnrollmentClaims claims;
    st = crypto::RandomArray(&claims.token_id);
    claims.product_id = a.get("product");
    claims.license_id = a.get("license");
    claims.issued_at_ms = UnixTimeMs();
    claims.expires_at_ms = claims.issued_at_ms + ttl;
    std::string token;
    if (st.ok()) st = proto::BuildEnrollmentToken(key, claims, &token);
    if (!st.ok()) return FailStatus("build token", st);
    std::printf("%s\n", token.c_str());
    SecureZero(&token[0], token.size());
    return 0;
}

// ---- licenses ------------------------------------------------------------------------------

int CmdLicense(const std::string& verb, const Args& a)
{
    if (!a.has("store") || !a.has("id")) return Fail("license commands need --store and --id");
    std::unique_ptr<ILicenseStore> store;
    Status st = CreateFileLicenseStore(a.get("store"), &store);
    if (!st.ok()) return FailOpen("open license store", st);
    if (verb == "add") {
        LicenseRecord rec;
        rec.license_id = a.get("id");
        rec.product_id = a.get("product");
        uint64_t seats = 0;
        if ((a.has("features") && !ParseU64(a.get("features"), &rec.features)) ||
            (a.has("expires-ms") && !ParseU64(a.get("expires-ms"), &rec.expires_at_ms)) ||
            (a.has("seats") && (!ParseU64(a.get("seats"), &seats) || seats > 0xFFFFFFFFull))) {
            return Fail("bad --features / --expires-ms / --seats");
        }
        rec.max_installations = static_cast<uint32_t>(seats);
        st = store->Upsert(rec);
        if (st == SG_INVALID_STATE) return Fail("add license: the license is revoked (revocation is permanent)");
        if (!st.ok()) return FailStatus("add license", st);
        std::printf("license %s saved\n", rec.license_id.c_str());
        return 0;
    }
    if (verb == "revoke") {
        st = store->Revoke(a.get("id"));
        if (!st.ok()) return FailStatus("revoke license", st);
        std::printf("license %s revoked\n", a.get("id").c_str());
        return 0;
    }
    if (verb == "show") {
        LicenseRecord rec;
        st = store->Find(a.get("id"), &rec);
        if (!st.ok()) return FailStatus("find license", st);
        std::printf("license:  %s\nproduct:  %s\nfeatures: 0x%llx\nexpires:  %llu (Unix ms, 0 = never)\n"
                    "seats:    %u used / %u (0 = unlimited)\nstatus:   %s\n",
                    rec.license_id.c_str(), rec.product_id.c_str(), static_cast<unsigned long long>(rec.features),
                    static_cast<unsigned long long>(rec.expires_at_ms), rec.seats_used, rec.max_installations,
                    rec.status == LicenseStatus::kActive ? "active" : "revoked");
        return 0;
    }
    return Fail("unknown license command: " + verb);
}

// ---- clients -------------------------------------------------------------------------------

int CmdClient(const std::string& verb, const Args& a)
{
    if (!a.has("registry")) return Fail("client commands need --registry");
    if (verb == "register") {
        if (const int rc = CheckBinding(a)) return rc;
    }
    std::unique_ptr<IClientRegistry> registry;
    Status st = CreateFileClientRegistry(a.get("registry"), &registry);
    if (!st.ok()) return FailOpen("open registry", st);
    if (verb == "register") {
        ClientRecord rec;
        if (!ParseHex(a.get("pubkey"), rec.public_key.data(), rec.public_key.size())) {
            return Fail("--pubkey must be the 65-byte SEC1 public key in hex (130 digits)");
        }
        st = proto::DeriveInstallationId(rec.public_key, &rec.installation_id);
        rec.product_id = a.get("product");
        rec.license_id = a.get("license");
        rec.created_at_ms = UnixTimeMs();
        if (st.ok()) st = registry->Register(rec);
        if (!st.ok()) return FailStatus("register client", st);
        std::printf("registered installation %s\n", ToHex(rec.installation_id).c_str());
        return 0;
    }
    if (verb == "revoke") {
        proto::InstallationId iid{};
        if (!ParseHex(a.get("iid"), iid.data(), iid.size())) return Fail("--iid must be 32 hex digits");
        st = registry->Revoke(iid);
        if (!st.ok()) return FailStatus("revoke client", st);
        std::printf("installation %s revoked\n", ToHex(iid).c_str());
        return 0;
    }
    if (verb == "list") {
        registry->ForEach([](const ClientRecord& r) {
            std::printf("%s  %-7s  product=%s  license=%s\n", ToHex(r.installation_id).c_str(),
                        r.status == ClientStatus::kActive ? "active" : "revoked", r.product_id.c_str(),
                        r.license_id.c_str());
        });
        return 0;
    }
    return Fail("unknown client command: " + verb);
}

// ---- development PKI -----------------------------------------------------------------------

struct PkeyFree {
    void operator()(EVP_PKEY* p) const { EVP_PKEY_free(p); }
};
struct X509Free {
    void operator()(X509* p) const { X509_free(p); }
};
struct BioFree {
    void operator()(BIO* p) const { BIO_free(p); }
};
using PkeyPtr = std::unique_ptr<EVP_PKEY, PkeyFree>;
using X509Ptr = std::unique_ptr<X509, X509Free>;
using BioPtr = std::unique_ptr<BIO, BioFree>;

bool AddExtension(X509* cert, X509* issuer, int nid, const char* value)
{
    X509V3_CTX ctx;
    X509V3_set_ctx_nodb(&ctx);
    X509V3_set_ctx(&ctx, issuer, cert, nullptr, nullptr, 0);
    X509_EXTENSION* ext = X509V3_EXT_conf_nid(nullptr, &ctx, nid, value);
    if (ext == nullptr) return false;
    const bool ok = X509_add_ext(cert, ext, -1) == 1;
    X509_EXTENSION_free(ext);
    return ok;
}

// Random positive 127-bit serial: regenerated certificates never collide.
bool SetRandomSerial(X509* cert)
{
    uint8_t bytes[16];
    if (!crypto::RandomBytes(bytes, sizeof(bytes)).ok()) return false;
    bytes[0] &= 0x7F;
    bytes[0] |= 0x01;
    BIGNUM* bn = BN_bin2bn(bytes, sizeof(bytes), nullptr);
    const bool ok = bn != nullptr && BN_to_ASN1_INTEGER(bn, X509_get_serialNumber(cert)) != nullptr;
    BN_free(bn);
    return ok;
}

bool AddName(X509_NAME* name, const char* field, const std::string& value)
{
    return X509_NAME_add_entry_by_txt(name, field, MBSTRING_UTF8, reinterpret_cast<const unsigned char*>(value.c_str()),
                                      -1, -1, 0) == 1;
}

X509Ptr MakeCert(EVP_PKEY* key, const std::string& cn, X509* issuer, long days)
{
    X509Ptr cert(X509_new());
    if (!cert || X509_set_version(cert.get(), 2) != 1 || !SetRandomSerial(cert.get()) ||
        X509_gmtime_adj(X509_getm_notBefore(cert.get()), -300) == nullptr ||
        X509_gmtime_adj(X509_getm_notAfter(cert.get()), days * 24 * 3600) == nullptr ||
        X509_set_pubkey(cert.get(), key) != 1) {
        return nullptr;
    }
    X509_NAME* name = X509_get_subject_name(cert.get());
    // The marker travels with the certificate, not only with the tool's output.
    if (!AddName(name, "O", "SockGate DEVELOPMENT ONLY") || !AddName(name, "CN", cn)) return nullptr;
    if (X509_set_issuer_name(cert.get(), issuer != nullptr ? X509_get_subject_name(issuer) : name) != 1) {
        return nullptr;
    }
    return cert;
}

std::string ToPem(X509* cert)
{
    BioPtr bio(BIO_new(BIO_s_mem()));
    std::string out;
    if (bio && PEM_write_bio_X509(bio.get(), cert) == 1) {
        char* data = nullptr;
        const long n = BIO_get_mem_data(bio.get(), &data);
        out.assign(data, static_cast<size_t>(n));
    }
    return out;
}

SecureBytes KeyPem(EVP_PKEY* key)
{
    // Secure-heap BIO: no stray copies of the key in freed memory.
    BioPtr bio(BIO_new(BIO_s_secmem()));
    SecureBytes out;
    if (bio && PEM_write_bio_PrivateKey(bio.get(), key, nullptr, nullptr, 0, nullptr, nullptr) == 1) {
        char* data = nullptr;
        const long n = BIO_get_mem_data(bio.get(), &data);
        out.assign(data, data + n);
    }
    return out;
}

bool IsIpAddress(const std::string& host)
{
    // Do not rely on the parser alone to refuse trailing text.
    if (host.empty() || host.find_first_not_of("0123456789abcdefABCDEF:.") != std::string::npos) return false;
    ASN1_OCTET_STRING* ip = a2i_IPADDRESS(host.c_str());
    ASN1_OCTET_STRING_free(ip);
    return ip != nullptr;
}

// A DNS name: letters, digits, '-' and '.', 1..63 per label (no SAN injection).
bool IsHostName(const std::string& host)
{
    if (host.empty() || host.size() > 253 || host.front() == '.' || host.back() == '.') return false;
    size_t label = 0;
    for (char c : host) {
        if (c == '.') {
            if (label == 0) return false;
            label = 0;
            continue;
        }
        const bool ok = (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') || (c >= '0' && c <= '9') || c == '-';
        if (!ok || ++label > 63) return false;
    }
    return true;
}

int CmdDevPki(const std::string& dir, const Args& a)
{
    const std::string host = a.get("host", "localhost");
    const bool ip = IsIpAddress(host);
    if (!ip && !IsHostName(host)) return Fail("--host must be a DNS name or an IP address");
    const std::string files[] = {dir + "/ca.crt", dir + "/server.crt", dir + "/server.key"};
    for (const std::string& f : files) {
        if (!MayWrite(f, a)) return 1;
    }

    PkeyPtr ca_key(EVP_PKEY_Q_keygen(nullptr, nullptr, "EC", "P-256"));
    PkeyPtr server_key(EVP_PKEY_Q_keygen(nullptr, nullptr, "EC", "P-256"));
    if (!ca_key || !server_key) return Fail("key generation failed");

    X509Ptr ca = MakeCert(ca_key.get(), "SockGate Development CA", nullptr, 365);
    if (!ca || !AddExtension(ca.get(), ca.get(), NID_basic_constraints, "critical,CA:TRUE,pathlen:0") ||
        !AddExtension(ca.get(), ca.get(), NID_key_usage, "critical,keyCertSign,cRLSign") ||
        !AddExtension(ca.get(), ca.get(), NID_subject_key_identifier, "hash") ||
        X509_sign(ca.get(), ca_key.get(), EVP_sha256()) == 0) {
        return Fail("CA certificate creation failed");
    }
    const std::string cn = host.size() <= 64 ? host : "SockGate development server";
    X509Ptr server = MakeCert(server_key.get(), cn, ca.get(), 90);
    const std::string san = (ip ? "IP:" : "DNS:") + host + (host == "127.0.0.1" ? "" : ",IP:127.0.0.1") +
                            (host == "::1" ? "" : ",IP:::1");
    if (!server || !AddExtension(server.get(), ca.get(), NID_basic_constraints, "critical,CA:FALSE") ||
        !AddExtension(server.get(), ca.get(), NID_key_usage, "critical,digitalSignature") ||
        !AddExtension(server.get(), ca.get(), NID_ext_key_usage, "serverAuth") ||
        !AddExtension(server.get(), ca.get(), NID_subject_alt_name, san.c_str()) ||
        !AddExtension(server.get(), ca.get(), NID_authority_key_identifier, "keyid") ||
        X509_sign(server.get(), ca_key.get(), EVP_sha256()) == 0) {
        return Fail("server certificate creation failed");
    }

    const std::string ca_pem = ToPem(ca.get());
    const std::string server_pem = ToPem(server.get());
    const SecureBytes key_pem = KeyPem(server_key.get());
    if (ca_pem.empty() || server_pem.empty() || key_pem.empty()) return Fail("PEM encoding failed");
    std::error_code ec;
    std::filesystem::create_directories(std::filesystem::u8path(dir), ec);
    auto write = [&](const std::string& path, ByteView data) {
        const Status st = WriteFileAtomically(path, data);  // owner-only
        if (!st.ok()) std::fprintf(stderr, "sg_admin: write %s: %s\n", path.c_str(), st.name());
        return st.ok();
    };
    if (!write(files[0], ser::AsBytes(ca_pem)) || !write(files[1], ser::AsBytes(server_pem)) ||
        !write(files[2], key_pem)) {
        return 1;
    }
    crypto::Sha256Digest pin;
    if (!tls::ComputeSpkiPinFromPem(ser::AsBytes(server_pem), &pin).ok()) return Fail("SPKI pin failed");
    std::printf("DEVELOPMENT ONLY - never use these files in production.\n"
                "  %s  CA to trust in clients (SG_ServerConfig.ca_file)\n"
                "  %s  server certificate, SAN %s (90 days)\n"
                "  %s  server private key\n"
                "  SPKI pin: %s\n",
                files[0].c_str(), files[1].c_str(), san.c_str(), files[2].c_str(), ToHex(pin).c_str());
    return 0;
}

void Usage()
{
    std::fprintf(stderr,
                 "usage:\n"
                 "  sg_admin pin <cert.pem>\n"
                 "  sg_admin token-key <file> [--force yes]\n"
                 "  sg_admin token issue --key FILE --product P [--license L [--licenses FILE]] [--ttl-ms N]\n"
                 "  sg_admin license add --store FILE --id L --product P [--features N] [--expires-ms N] "
                 "[--seats N]\n"
                 "  sg_admin license revoke|show --store FILE --id L\n"
                 "  sg_admin client register --registry FILE --pubkey HEX [--product P]\n"
                 "                           [--license L [--licenses FILE]]\n"
                 "  sg_admin client revoke --registry FILE --iid HEX\n"
                 "  sg_admin client list --registry FILE\n"
                 "  sg_admin dev-pki <dir> [--host NAME] [--force yes]   (development only)\n"
                 "Numbers are decimal or 0x-prefixed hex. Stores are locked by a running server:\n"
                 "edit them while it is stopped.\n");
}

int Run(int argc, char** argv)
{
    if (argc < 3) {
        Usage();
        return 2;
    }
    const std::string cmd = argv[1];
    const std::string word = argv[2];
    if (word.empty() || word[0] == '-') {  // e.g. "token-key --force" must not write a file named "--force"
        Usage();
        return 2;
    }
    auto parse = [&](int first, std::set<std::string> allowed, Args* out) {
        *out = ParseArgs(argc, argv, first, allowed);
        if (!out->error.empty()) std::fprintf(stderr, "sg_admin: %s\n", out->error.c_str());
        return out->error.empty();
    };
    Args a;
    if (cmd == "pin" && argc == 3) return CmdPin(word);
    if (cmd == "token-key") return parse(3, {"force"}, &a) ? CmdTokenKey(word, a) : 2;
    if (cmd == "dev-pki") return parse(3, {"host", "force"}, &a) ? CmdDevPki(word, a) : 2;
    if (cmd == "token" && word == "issue") {
        return parse(3, {"key", "product", "license", "licenses", "ttl-ms"}, &a) ? CmdTokenIssue(a) : 2;
    }
    if (cmd == "license" && word == "add") {
        return parse(3, {"store", "id", "product", "features", "expires-ms", "seats"}, &a) ? CmdLicense(word, a) : 2;
    }
    if (cmd == "license" && (word == "revoke" || word == "show")) {
        return parse(3, {"store", "id"}, &a) ? CmdLicense(word, a) : 2;
    }
    if (cmd == "client" && word == "register") {
        return parse(3, {"registry", "pubkey", "product", "license", "licenses"}, &a) ? CmdClient(word, a) : 2;
    }
    if (cmd == "client" && word == "revoke") return parse(3, {"registry", "iid"}, &a) ? CmdClient(word, a) : 2;
    if (cmd == "client" && word == "list") return parse(3, {"registry"}, &a) ? CmdClient(word, a) : 2;
    Usage();
    return 2;
}

}  // namespace

int main(int argc, char** argv)
{
    try {
        return Run(argc, argv);
    } catch (const std::exception& e) {
        return Fail(e.what());
    }
}
