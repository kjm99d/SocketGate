// C ABI of the SockGate server library.
#include <sockgate/server.h>

#include "core/server_engine.h"
#include "storage/atomic_file.h"

#include "sockgate_common/core/abi.h"
#include "sockgate_common/crypto/crypto.h"
#include "sockgate_common/protocol/transcript.h"

#include <algorithm>
#include <cctype>
#include <cstddef>
#include <cstring>
#include <filesystem>
#include <new>
#include <string>
#include <system_error>

SG_ASSERT_NO_TAIL_PADDING(SG_ServerOptions, allowed_executable_count);
SG_ASSERT_NO_TAIL_PADDING(SG_ServerCallbacks, on_session_closed);
SG_ASSERT_NO_TAIL_PADDING(SG_ClientRecord, license_id);
SG_ASSERT_NO_TAIL_PADDING(SG_EnrollmentTokenRequest, reserved);
SG_ASSERT_NO_TAIL_PADDING(SG_LicenseRecord, reserved);

struct SG_Server {
    // Declared before `engine`: the engine's callbacks point into this copy,
    // so it must outlive the engine (members are destroyed in reverse order).
    SG_ServerCallbacks callbacks{};
    bool has_callbacks = false;
    std::unique_ptr<sg::server::ServerEngine> engine;
};

namespace {

using sg::Status;

#define SG_HAS_FIELD(ptr, type, field) \
    ((ptr)->size >= offsetof(type, field) + sizeof(((type*)nullptr)->field))

template <class F>
SG_Status Guard(F&& fn) noexcept
{
    try {
        return sg::ToPublicStatus(fn());
    } catch (const std::bad_alloc&) {
        return SG_OUT_OF_MEMORY;
    } catch (...) {
        return SG_INTERNAL_ERROR;
    }
}

bool CopyCString(const char* in, size_t max, std::string* out)
{
    out->clear();
    if (in == nullptr) return true;
    size_t n = 0;
    while (in[n] != '\0') {
        if (++n > max) return false;
    }
    out->assign(in, n);
    return true;
}

Status LoadPem(const char* file, const char* pem, size_t pem_size, std::string* out_text, sg::SecureBytes* out_secure)
{
    std::string path;
    if (!CopyCString(file, 4096, &path)) return SG_INVALID_ARGUMENT;
    if (!path.empty()) {
        sg::Bytes data;
        SG_TRY(sg::server::ReadWholeFile(path, &data));
        if (out_text != nullptr) out_text->assign(data.begin(), data.end());
        if (out_secure != nullptr) out_secure->assign(data.begin(), data.end());
        sg::SecureZero(data.data(), data.size());
        return sg::OkStatus();
    }
    if (pem != nullptr) {
        const size_t n = pem_size != 0 ? pem_size : std::strlen(pem);
        if (n > 16u * 1024 * 1024) return SG_INVALID_ARGUMENT;
        if (out_text != nullptr) out_text->assign(pem, n);
        if (out_secure != nullptr) out_secure->assign(pem, pem + n);
    }
    return sg::OkStatus();
}

void CopyField(char* dst, size_t cap, const std::string& src)
{
    const size_t n = src.size() < cap - 1 ? src.size() : cap - 1;
    std::memcpy(dst, src.data(), n);
    dst[n] = '\0';
}

void FillSessionInfo(const sg::server::SessionSnapshot& s, SG_ServerSessionInfo* out)
{
    out->session = s.handle;
    std::memcpy(out->session_id.bytes, s.session_id.data(), s.session_id.size());
    std::memcpy(out->installation_id.bytes, s.installation_id.data(), s.installation_id.size());
    out->policy = static_cast<uint32_t>(s.policy);
    out->epoch = s.epoch;
    out->granted_features = s.granted_features;
    out->license_expires_at_ms = s.license_expires_at_ms;
    out->expires_in_ms = s.expires_in_ms > 0xFFFFFFFFu ? 0xFFFFFFFFu : static_cast<uint32_t>(s.expires_in_ms);
    out->enrolled = s.enrolled ? 1u : 0u;
    CopyField(out->peer_address, sizeof(out->peer_address), s.peer_address);
    CopyField(out->product_id, sizeof(out->product_id), s.product_id);
    CopyField(out->license_id, sizeof(out->license_id), s.license_id);
    if (SG_HAS_FIELD(out, SG_ServerSessionInfo, license_status)) {
        out->license_status = static_cast<uint32_t>(s.license_status);
    }
}

// True if both paths (existing or not) resolve to the same file.
bool SameFile(const std::string& a, const std::string& b)
{
    namespace fs = std::filesystem;
    std::error_code ec_a;
    std::error_code ec_b;
    const fs::path pa = fs::u8path(a);
    const fs::path pb = fs::u8path(b);
    if (fs::exists(pa, ec_a) && fs::exists(pb, ec_b)) {
        std::error_code ec;
        if (fs::equivalent(pa, pb, ec)) return true;
    }
    std::error_code ec1;
    std::error_code ec2;
    std::string ca = fs::weakly_canonical(pa, ec1).u8string();
    std::string cb = fs::weakly_canonical(pb, ec2).u8string();
    if (ec1 || ec2) return a == b;
#ifdef _WIN32
    auto lower = [](std::string& v) {
        std::transform(v.begin(), v.end(), v.begin(), [](unsigned char c) { return static_cast<char>(std::tolower(c)); });
    };
    lower(ca);
    lower(cb);
#endif
    return ca == cb;
}

// Bridges engine callbacks to the application's C callbacks.
sg::server::EngineCallbacks BridgeCallbacks(SG_Server* server)
{
    sg::server::EngineCallbacks cb;
    if (!server->has_callbacks) return cb;
    const SG_ServerCallbacks* c = &server->callbacks;

    if (c->on_authorize != nullptr) {
        cb.authorize = [c](SG_SessionHandle handle, const sg::server::AuthorizationRequest& r,
                           sg::server::AuthorizationDecision* d) -> Status {
            SG_AuthRequest req;
            std::memset(&req, 0, sizeof(req));
            req.size = sizeof(req);
            req.version = SG_AUTH_REQUEST_VERSION;
            req.session = handle;
            std::memcpy(req.installation_id.bytes, r.installation_id.data(), r.installation_id.size());
            req.auth_mode = static_cast<uint32_t>(r.mode);
            req.reauthentication = r.reauthentication ? 1u : 0u;
            req.product_id = r.product_id.c_str();
            req.product_version = r.product_version.c_str();
            req.license_id = r.license_id.c_str();
            req.requested_features = r.has_requested_features ? r.requested_features : 0;
            req.client_version_major = r.client_version_major;
            req.client_version_minor = r.client_version_minor;
            req.client_version_patch = r.client_version_patch;
            req.integrity_present = r.has_integrity ? 1 : 0;
            req.integrity_flags = r.has_integrity ? r.integrity.observation_flags : 0;
            req.integrity_platform = r.has_integrity ? r.integrity.platform : 0;
            req.executable_sha256 = r.has_integrity ? r.integrity.executable_sha256.data() : nullptr;
            req.peer_address = r.peer_address.c_str();
            static const char kEmpty[] = "";
            req.registered_product_id = r.record != nullptr ? r.record->product_id.c_str() : kEmpty;
            req.registered_license_id = r.record != nullptr ? r.record->license_id.c_str() : kEmpty;
            req.license_status = static_cast<uint32_t>(r.license_status);
            req.license_features = r.license_features;
            req.integrity_conditions = r.integrity_conditions;

            SG_AuthDecision dec;
            std::memset(&dec, 0, sizeof(dec));
            dec.size = sizeof(dec);
            dec.version = SG_AUTH_DECISION_VERSION;
            dec.allow = d->allow ? 1u : 0u;
            dec.policy = static_cast<uint32_t>(d->policy);
            dec.granted_features = d->granted_features;
            dec.session_lifetime_ms = d->session_lifetime_ms;
            dec.license_expires_at_ms = d->license_expires_at_ms;

            const SG_Status st = c->on_authorize(c->user, &req, &dec);
            if (st != SG_OK) return SG_SERVER_REJECTED;
            if (dec.policy != SG_SESSION_POLICY_NORMAL && dec.policy != SG_SESSION_POLICY_RESTRICTED) {
                return SG_INVALID_ARGUMENT;  // treated as a denial
            }
            d->allow = dec.allow != 0;
            d->policy = static_cast<sg::proto::SessionPolicy>(dec.policy);
            d->granted_features = dec.granted_features;
            d->session_lifetime_ms = dec.session_lifetime_ms;
            d->license_expires_at_ms = dec.license_expires_at_ms;
            return sg::OkStatus();
        };
    }
    if (c->on_enroll != nullptr) {
        cb.enroll = [c](const sg::server::EnrollmentRequest& r, sg::crypto::Sha256Digest* k_tok) -> Status {
            SG_EnrollRequest req;
            std::memset(&req, 0, sizeof(req));
            req.size = sizeof(req);
            req.version = SG_ENROLL_REQUEST_VERSION;
            std::memcpy(req.installation_id.bytes, r.installation_id.data(), r.installation_id.size());
            std::memcpy(req.public_key.bytes, r.public_key.data(), r.public_key.size());
            req.token_pub = r.token_pub.data();
            req.token_pub_size = r.token_pub.size();
            req.product_id = r.product_id.c_str();
            req.license_id = r.license_id.c_str();
            req.peer_address = r.peer_address.c_str();
            uint8_t key[32] = {};
            sg::server::CallbackScope scope;
            const SG_Status st = c->on_enroll(c->user, &req, key);
            std::memcpy(k_tok->data(), key, sizeof(key));
            sg::SecureZero(key, sizeof(key));
            return st == SG_OK ? sg::OkStatus() : Status(SG_AUTH_FAILED);
        };
    }
    if (c->on_session_opened != nullptr) {
        cb.session_opened = [c](const sg::server::SessionSnapshot& s) {
            SG_ServerSessionInfo info;
            std::memset(&info, 0, sizeof(info));
            info.size = sizeof(info);
            info.version = SG_SERVER_SESSION_INFO_VERSION;
            FillSessionInfo(s, &info);
            c->on_session_opened(c->user, &info);
        };
    }
    if (c->on_message != nullptr) {
        cb.message = [c](SG_SessionHandle h, const uint8_t* data, size_t size, uint64_t request_id, uint32_t flags) {
            SG_MessageInfo info;
            std::memset(&info, 0, sizeof(info));
            info.size = sizeof(info);
            info.version = SG_MESSAGE_INFO_VERSION;
            info.request_id = request_id;
            info.flags = flags;
            c->on_message(c->user, h, data, size, &info);
        };
    }
    if (c->on_session_closed != nullptr) {
        cb.session_closed = [c](SG_SessionHandle h, SG_Status reason) { c->on_session_closed(c->user, h, reason); };
    }
    return cb;
}

Status ParseOptions(const SG_ServerOptions* o, SG_Server* server, sg::server::EngineConfig* cfg)
{
    if (o->version == 0 || !SG_HAS_FIELD(o, SG_ServerOptions, tls_private_key_pem_size)) return SG_INVALID_ARGUMENT;
    SG_TRY(sg::CheckUnknownTail(o, o->size, sizeof(SG_ServerOptions)));
    std::string bind;
    if (!CopyCString(o->bind_address, 253, &bind)) return SG_INVALID_ARGUMENT;
    if (!bind.empty()) cfg->bind_address = bind;
    cfg->port = o->port;

    std::string chain_file;
    std::string key_file;
    if (!CopyCString(o->tls_cert_chain_file, 4096, &chain_file) || !CopyCString(o->tls_private_key_file, 4096, &key_file)) {
        return SG_INVALID_ARGUMENT;
    }
    cfg->tls.cert_chain_file = chain_file;
    cfg->tls.private_key_file = key_file;
    if (chain_file.empty()) SG_TRY(LoadPem(nullptr, o->tls_cert_chain_pem, o->tls_cert_chain_pem_size, &cfg->tls.cert_chain_pem, nullptr));
    if (key_file.empty()) SG_TRY(LoadPem(nullptr, o->tls_private_key_pem, o->tls_private_key_pem_size, nullptr, &cfg->tls.private_key_pem));

    uint32_t flags = 0;
    if (SG_HAS_FIELD(o, SG_ServerOptions, flags)) flags = o->flags;
    cfg->tls.allow_tls12 = (flags & SG_SERVER_OPT_ALLOW_TLS12) != 0;
    cfg->require_app_encryption = (flags & SG_SERVER_OPT_REQUIRE_APP_ENCRYPTION) != 0;
    cfg->handshake.allow_enrollment = (flags & SG_SERVER_OPT_ALLOW_ENROLLMENT) != 0;
    cfg->require_license = (flags & SG_SERVER_OPT_REQUIRE_LICENSE) != 0;
    cfg->allow_license_activation = (flags & SG_SERVER_OPT_LICENSE_ACTIVATION) != 0;
    // Refuse options this build cannot honour instead of silently ignoring them.
    if ((flags & ~(SG_SERVER_OPT_ALLOW_TLS12 | SG_SERVER_OPT_REQUIRE_APP_ENCRYPTION | SG_SERVER_OPT_ALLOW_ENROLLMENT |
                   SG_SERVER_OPT_REQUIRE_LICENSE | SG_SERVER_OPT_LICENSE_ACTIVATION)) != 0) {
        return SG_NOT_SUPPORTED;
    }

    if (SG_HAS_FIELD(o, SG_ServerOptions, proof_key_pem_size)) {
        sg::SecureBytes pem;
        SG_TRY(LoadPem(o->proof_key_file, o->proof_key_pem, o->proof_key_pem_size, nullptr, &pem));
        if (!pem.empty()) {
            std::unique_ptr<sg::crypto::SoftwareP256Key> key;
            SG_TRY(sg::crypto::SoftwareP256Key::FromPem(pem, &key));
            cfg->handshake.proof_key = std::shared_ptr<const sg::crypto::SoftwareP256Key>(std::move(key));
        }
    }
    if (SG_HAS_FIELD(o, SG_ServerOptions, token_key_size) && o->token_key != nullptr && o->token_key_size != 0) {
        if (o->token_key_size < 32 || o->token_key_size > 1024) return SG_INVALID_ARGUMENT;
        cfg->handshake.token_key.assign(o->token_key, o->token_key + o->token_key_size);
    }
    if (SG_HAS_FIELD(o, SG_ServerOptions, registry_path) && !CopyCString(o->registry_path, 4096, &cfg->registry_path)) {
        return SG_INVALID_ARGUMENT;
    }
    if (SG_HAS_FIELD(o, SG_ServerOptions, flags)) {
        if (o->worker_threads != 0) cfg->worker_threads = o->worker_threads;
        if (o->max_connections != 0) cfg->max_connections = o->max_connections;
        if (o->handshake_timeout_ms != 0) cfg->handshake_timeout_ms = o->handshake_timeout_ms;
        if (o->challenge_ttl_ms != 0) cfg->handshake.challenge_ttl_ms = o->challenge_ttl_ms;
        if (o->session_lifetime_ms != 0) {
            cfg->handshake.default_session_lifetime_ms = o->session_lifetime_ms;
            if (cfg->handshake.max_session_lifetime_ms < o->session_lifetime_ms) return SG_INVALID_ARGUMENT;
        }
        cfg->idle_timeout_ms = o->idle_timeout_ms;
        if (o->max_payload_size != 0) cfg->max_payload = o->max_payload_size;
        if (o->min_reauth_interval_ms != 0) cfg->min_reauth_interval_ms = o->min_reauth_interval_ms;
    }
    if (SG_HAS_FIELD(o, SG_ServerOptions, callbacks) && o->callbacks != nullptr) {
        const SG_ServerCallbacks* c = o->callbacks;
        if (c->version == 0 || !SG_HAS_FIELD(c, SG_ServerCallbacks, user)) return SG_INVALID_ARGUMENT;
        SG_TRY(sg::CheckUnknownTail(c, c->size, sizeof(SG_ServerCallbacks)));
        // Copy field by field: a caller size ending inside a function pointer
        // must never produce a half-copied pointer.
        SG_ServerCallbacks& dst = server->callbacks;
        std::memset(&dst, 0, sizeof(dst));
        dst.size = sizeof(dst);
        dst.version = SG_SERVER_CALLBACKS_VERSION;
        dst.user = c->user;
        if (SG_HAS_FIELD(c, SG_ServerCallbacks, on_authorize)) dst.on_authorize = c->on_authorize;
        if (SG_HAS_FIELD(c, SG_ServerCallbacks, on_enroll)) dst.on_enroll = c->on_enroll;
        if (SG_HAS_FIELD(c, SG_ServerCallbacks, on_session_opened)) dst.on_session_opened = c->on_session_opened;
        if (SG_HAS_FIELD(c, SG_ServerCallbacks, on_message)) dst.on_message = c->on_message;
        if (SG_HAS_FIELD(c, SG_ServerCallbacks, on_session_closed)) dst.on_session_closed = c->on_session_closed;
        server->has_callbacks = true;
    }
    if (SG_HAS_FIELD(o, SG_ServerOptions, log_level)) {
        cfg->logger = sg::Logger(o->log_callback, o->log_user, o->log_level);
    }
    if (SG_HAS_FIELD(o, SG_ServerOptions, license_path) && !CopyCString(o->license_path, 4096, &cfg->license_path)) {
        return SG_INVALID_ARGUMENT;
    }
    if (!cfg->registry_path.empty() && !cfg->license_path.empty() && SameFile(cfg->registry_path, cfg->license_path)) {
        return SG_INVALID_ARGUMENT;
    }
    if (SG_HAS_FIELD(o, SG_ServerOptions, allowed_executable_count)) {
        constexpr uint32_t kKnownConditions =
            SG_INTEGRITY_KNOWN_FLAGS | SG_INTEGRITY_REPORT_MISSING | SG_INTEGRITY_UNKNOWN_EXECUTABLE;
        if (((o->integrity_restrict_mask | o->integrity_reject_mask) & ~kKnownConditions) != 0) {
            return SG_NOT_SUPPORTED;  // a condition this build cannot evaluate
        }
        cfg->integrity.restrict_mask = o->integrity_restrict_mask;
        cfg->integrity.reject_mask = o->integrity_reject_mask;
        if (o->allowed_executable_count > 4096 ||
            (o->allowed_executable_count != 0 && o->allowed_executables == nullptr)) {
            return SG_INVALID_ARGUMENT;
        }
        for (size_t i = 0; i < o->allowed_executable_count; ++i) {
            sg::crypto::Sha256Digest digest;
            std::memcpy(digest.data(), o->allowed_executables[i].bytes, digest.size());
            // An all-zero entry would match every report whose hash failed.
            if (std::all_of(digest.begin(), digest.end(), [](uint8_t b) { return b == 0; })) {
                return SG_INVALID_ARGUMENT;
            }
            cfg->integrity.allowed_executables.push_back(digest);
        }
    }
    return sg::OkStatus();
}

}  // namespace

extern "C" {

SG_SERVER_API void SG_CALL SG_ServerOptions_Init(SG_ServerOptions* options)
{
    if (options == nullptr) return;
    std::memset(options, 0, sizeof(*options));
    options->size = sizeof(*options);
    options->version = SG_SERVER_OPTIONS_VERSION;
    options->max_connections = 10000;
    options->handshake_timeout_ms = 15000;
    options->challenge_ttl_ms = 30000;
    options->session_lifetime_ms = 3600000;
    options->idle_timeout_ms = 300000;
    options->max_payload_size = 1u << 20;
    options->min_reauth_interval_ms = 10000;
    options->log_level = SG_LOG_WARN;
}

SG_SERVER_API void SG_CALL SG_ServerCallbacks_Init(SG_ServerCallbacks* callbacks)
{
    if (callbacks == nullptr) return;
    std::memset(callbacks, 0, sizeof(*callbacks));
    callbacks->size = sizeof(*callbacks);
    callbacks->version = SG_SERVER_CALLBACKS_VERSION;
}

SG_SERVER_API void SG_CALL SG_ClientRecord_Init(SG_ClientRecord* record)
{
    if (record == nullptr) return;
    std::memset(record, 0, sizeof(*record));
    record->size = sizeof(*record);
    record->version = SG_CLIENT_RECORD_VERSION;
}

SG_SERVER_API void SG_CALL SG_EnrollmentTokenRequest_Init(SG_EnrollmentTokenRequest* request)
{
    if (request == nullptr) return;
    std::memset(request, 0, sizeof(*request));
    request->size = sizeof(*request);
    request->version = SG_ENROLLMENT_TOKEN_REQUEST_VERSION;
}

SG_SERVER_API void SG_CALL SG_LicenseRecord_Init(SG_LicenseRecord* record)
{
    if (record == nullptr) return;
    std::memset(record, 0, sizeof(*record));
    record->size = sizeof(*record);
    record->version = SG_LICENSE_RECORD_VERSION;
}

SG_SERVER_API void SG_CALL SG_LicenseInfo_Init(SG_LicenseInfo* info)
{
    if (info == nullptr) return;
    std::memset(info, 0, sizeof(*info));
    info->size = sizeof(*info);
    info->version = SG_LICENSE_INFO_VERSION;
}

SG_SERVER_API void SG_CALL SG_ServerSessionInfo_Init(SG_ServerSessionInfo* info)
{
    if (info == nullptr) return;
    std::memset(info, 0, sizeof(*info));
    info->size = sizeof(*info);
    info->version = SG_SERVER_SESSION_INFO_VERSION;
}

SG_SERVER_API void SG_CALL SG_ServerStats_Init(SG_ServerStats* stats)
{
    if (stats == nullptr) return;
    std::memset(stats, 0, sizeof(*stats));
    stats->size = sizeof(*stats);
    stats->version = SG_SERVER_STATS_VERSION;
}

SG_SERVER_API SG_Status SG_CALL SG_Server_Create(const SG_ServerOptions* options, SG_Server** server)
{
    if (options == nullptr || server == nullptr) return SG_INVALID_ARGUMENT;
    *server = nullptr;
    return Guard([&]() -> Status {
        auto handle = std::make_unique<SG_Server>();
        sg::server::EngineConfig config;
        SG_TRY(ParseOptions(options, handle.get(), &config));
        sg::server::EngineCallbacks callbacks = BridgeCallbacks(handle.get());
        SG_TRY(sg::server::ServerEngine::Create(std::move(config), std::move(callbacks), &handle->engine));
        *server = handle.release();
        return sg::OkStatus();
    });
}

SG_SERVER_API SG_Status SG_CALL SG_Server_Start(SG_Server* server)
{
    if (server == nullptr) return SG_INVALID_ARGUMENT;
    // A callback delivered by SG_Server_Stop runs under the lifecycle lock.
    if (sg::server::InApplicationCallback()) return SG_INVALID_STATE;
    return Guard([&]() { return server->engine->Start(); });
}

SG_SERVER_API SG_Status SG_CALL SG_Server_Stop(SG_Server* server)
{
    if (server == nullptr) return SG_INVALID_ARGUMENT;
    if (sg::server::InApplicationCallback()) return SG_INVALID_STATE;
    return Guard([&]() -> Status {
        server->engine->Stop();
        return sg::OkStatus();
    });
}

SG_SERVER_API SG_Status SG_CALL SG_Server_Destroy(SG_Server* server)
{
    if (server == nullptr) return SG_OK;
    if (sg::server::InApplicationCallback()) return SG_INVALID_STATE;
    return Guard([&]() -> Status {
        server->engine->Stop();
        delete server;
        return sg::OkStatus();
    });
}

SG_SERVER_API SG_Status SG_CALL SG_Server_GetPort(SG_Server* server, uint16_t* port)
{
    if (server == nullptr || port == nullptr) return SG_INVALID_ARGUMENT;
    *port = server->engine->port();
    return *port != 0 ? SG_OK : SG_INVALID_STATE;
}

SG_SERVER_API SG_Status SG_CALL SG_Server_Send(SG_Server* server, SG_SessionHandle session, const void* data,
                                               size_t size)
{
    return SG_Server_SendEx(server, session, data, size, 0);
}

SG_SERVER_API SG_Status SG_CALL SG_Server_SendEx(SG_Server* server, SG_SessionHandle session, const void* data,
                                                 size_t size, uint64_t reply_to_request_id)
{
    if (server == nullptr || (data == nullptr && size != 0)) return SG_INVALID_ARGUMENT;
    return Guard([&]() {
        return server->engine->Send(session, sg::ByteView(static_cast<const uint8_t*>(data), size), reply_to_request_id);
    });
}

SG_SERVER_API SG_Status SG_CALL SG_Server_CloseSession(SG_Server* server, SG_SessionHandle session)
{
    if (server == nullptr) return SG_INVALID_ARGUMENT;
    return Guard([&]() { return server->engine->CloseSession(session); });
}

SG_SERVER_API SG_Status SG_CALL SG_Server_GetSessionInfo(SG_Server* server, SG_SessionHandle session,
                                                         SG_ServerSessionInfo* info)
{
    if (server == nullptr || info == nullptr || !SG_HAS_FIELD(info, SG_ServerSessionInfo, license_id)) {
        return SG_INVALID_ARGUMENT;
    }
    return Guard([&]() -> Status {
        sg::server::SessionSnapshot snapshot;
        SG_TRY(server->engine->GetSession(session, &snapshot));
        FillSessionInfo(snapshot, info);
        return sg::OkStatus();
    });
}

SG_SERVER_API SG_Status SG_CALL SG_Server_RegisterClient(SG_Server* server, const SG_ClientRecord* record)
{
    if (server == nullptr || record == nullptr || record->version == 0 ||
        !SG_HAS_FIELD(record, SG_ClientRecord, public_key)) {
        return SG_INVALID_ARGUMENT;
    }
    return Guard([&]() -> Status {
        SG_TRY(sg::CheckUnknownTail(record, record->size, sizeof(SG_ClientRecord)));
        sg::server::ClientRecord rec;
        std::memcpy(rec.public_key.data(), record->public_key.bytes, rec.public_key.size());
        SG_TRY(sg::crypto::ValidateP256PublicKey(rec.public_key));
        SG_TRY(sg::proto::DeriveInstallationId(rec.public_key, &rec.installation_id));
        if (SG_HAS_FIELD(record, SG_ClientRecord, license_id)) {
            if (!CopyCString(record->product_id, sg::proto::kMaxProductIdLength, &rec.product_id) ||
                !CopyCString(record->license_id, sg::proto::kMaxLicenseIdLength, &rec.license_id)) {
                return SG_INVALID_ARGUMENT;
            }
        }
        return server->engine->RegisterClient(rec);
    });
}

SG_SERVER_API SG_Status SG_CALL SG_Server_RevokeClient(SG_Server* server, const SG_InstallationId* installation_id)
{
    if (server == nullptr || installation_id == nullptr) return SG_INVALID_ARGUMENT;
    return Guard([&]() {
        sg::proto::InstallationId id;
        std::memcpy(id.data(), installation_id->bytes, id.size());
        return server->engine->RevokeClient(id);
    });
}

SG_SERVER_API SG_Status SG_CALL SG_Server_IssueEnrollmentToken(SG_Server* server,
                                                               const SG_EnrollmentTokenRequest* request, char* token,
                                                               size_t capacity, size_t* written)
{
    if (server == nullptr || request == nullptr || written == nullptr || request->version == 0 ||
        !SG_HAS_FIELD(request, SG_EnrollmentTokenRequest, ttl_ms)) {
        return SG_INVALID_ARGUMENT;
    }
    *written = 0;
    return Guard([&]() -> Status {
        SG_TRY(sg::CheckUnknownTail(request, request->size, sizeof(SG_EnrollmentTokenRequest)));
        std::string product;
        std::string license;
        if (!CopyCString(request->product_id, sg::proto::kMaxProductIdLength, &product) ||
            !CopyCString(request->license_id, sg::proto::kMaxLicenseIdLength, &license) || product.empty()) {
            return SG_INVALID_ARGUMENT;
        }
        std::string out;
        SG_TRY(server->engine->IssueEnrollmentToken(product, license, request->ttl_ms, &out));
        *written = out.size() + 1;
        Status st = sg::OkStatus();
        if (token == nullptr || capacity < out.size() + 1) {
            st = SG_BUFFER_TOO_SMALL;
        } else {
            std::memcpy(token, out.c_str(), out.size() + 1);
        }
        sg::SecureZero(&out[0], out.size());
        return st;
    });
}

SG_SERVER_API SG_Status SG_CALL SG_Server_AddLicense(SG_Server* server, const SG_LicenseRecord* license)
{
    if (server == nullptr || license == nullptr || license->version == 0 ||
        !SG_HAS_FIELD(license, SG_LicenseRecord, max_installations)) {
        return SG_INVALID_ARGUMENT;
    }
    return Guard([&]() -> Status {
        SG_TRY(sg::CheckUnknownTail(license, license->size, sizeof(SG_LicenseRecord)));
        sg::server::LicenseRecord rec;
        if (!CopyCString(license->license_id, sg::proto::kMaxLicenseIdLength, &rec.license_id) ||
            !CopyCString(license->product_id, sg::proto::kMaxProductIdLength, &rec.product_id)) {
            return SG_INVALID_ARGUMENT;
        }
        rec.features = license->features;
        rec.expires_at_ms = license->expires_at_ms;
        rec.max_installations = license->max_installations;
        return server->engine->AddLicense(rec);
    });
}

SG_SERVER_API SG_Status SG_CALL SG_Server_RevokeLicense(SG_Server* server, const char* license_id)
{
    if (server == nullptr || license_id == nullptr) return SG_INVALID_ARGUMENT;
    return Guard([&]() -> Status {
        std::string id;
        if (!CopyCString(license_id, sg::proto::kMaxLicenseIdLength, &id) || id.empty()) return SG_INVALID_ARGUMENT;
        return server->engine->RevokeLicense(id);
    });
}

SG_SERVER_API SG_Status SG_CALL SG_Server_ReleaseLicenseSeat(SG_Server* server, const char* license_id,
                                                             const SG_InstallationId* installation_id)
{
    if (server == nullptr || license_id == nullptr || installation_id == nullptr) return SG_INVALID_ARGUMENT;
    return Guard([&]() -> Status {
        std::string id;
        if (!CopyCString(license_id, sg::proto::kMaxLicenseIdLength, &id) || id.empty()) return SG_INVALID_ARGUMENT;
        sg::proto::InstallationId iid;
        std::memcpy(iid.data(), installation_id->bytes, iid.size());
        return server->engine->ReleaseLicenseSeat(id, iid);
    });
}

SG_SERVER_API SG_Status SG_CALL SG_Server_GetLicense(SG_Server* server, const char* license_id, SG_LicenseInfo* info)
{
    if (server == nullptr || license_id == nullptr || info == nullptr || !SG_HAS_FIELD(info, SG_LicenseInfo, revoked)) {
        return SG_INVALID_ARGUMENT;
    }
    return Guard([&]() -> Status {
        std::string id;
        if (!CopyCString(license_id, sg::proto::kMaxLicenseIdLength, &id) || id.empty()) return SG_INVALID_ARGUMENT;
        sg::server::LicenseRecord rec;
        SG_TRY(server->engine->GetLicense(id, &rec));
        CopyField(info->product_id, sizeof(info->product_id), rec.product_id);
        info->features = rec.features;
        info->expires_at_ms = rec.expires_at_ms;
        info->max_installations = rec.max_installations;
        info->installations = rec.seats_used;
        info->revoked = rec.status == sg::server::LicenseStatus::kRevoked ? 1u : 0u;
        return sg::OkStatus();
    });
}

SG_SERVER_API SG_Status SG_CALL SG_Server_GetStats(SG_Server* server, SG_ServerStats* stats)
{
    if (server == nullptr || stats == nullptr || !SG_HAS_FIELD(stats, SG_ServerStats, messages_sent)) {
        return SG_INVALID_ARGUMENT;
    }
    return Guard([&]() -> Status {
        const auto& s = server->engine->stats();
        stats->active_connections = server->engine->ActiveConnections();
        stats->active_sessions = server->engine->ActiveSessions();
        stats->total_connections = s.total_connections.load();
        stats->auth_succeeded = s.auth_succeeded.load();
        stats->auth_failed = s.auth_failed.load();
        stats->protocol_errors = s.protocol_errors.load();
        stats->messages_received = s.messages_received.load();
        stats->messages_sent = s.messages_sent.load();
        return sg::OkStatus();
    });
}

SG_SERVER_API uint32_t SG_CALL SG_Server_GetApiVersion(void) { return SOCKGATE_API_VERSION; }

}  // extern "C"
