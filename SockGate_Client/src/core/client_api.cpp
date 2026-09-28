// C ABI of the SockGate client library.
//
// Every entry point validates its arguments, reads versioned structures only
// within their declared size, and converts C++ exceptions into status codes:
// nothing but SG_Status values ever crosses the ABI boundary.
#include <sockgate/client.h>

#include "crypto/key_store_factory.h"
#include "session/client_session.h"

#include "sockgate_common/tls/tls.h"

#include <cstddef>
#include <cstring>
#include <new>
#include <string>

struct SG_Client {
    std::unique_ptr<sg::client::ClientSession> session;
};

namespace {

using sg::Status;

// True when `field` of the caller's structure lies within its declared size.
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

// Copies a NUL-terminated string of at most `max` bytes. Scans byte by byte
// and stops at the terminator, never reading past it.
bool CopyCString(const char* in, size_t max, std::string* out)
{
    out->clear();
    if (in == nullptr) return true;
    size_t n = 0;
    while (in[n] != '\0') {
        if (++n > max) return false;  // longer than allowed
    }
    out->assign(in, n);
    return true;
}

Status ParseProxy(const SG_ProxyConfig* p, sg::client::ProxySettings* out)
{
    if (p == nullptr) return sg::OkStatus();
    if (p->size < offsetof(SG_ProxyConfig, mode) + sizeof(p->mode) || p->version == 0) return SG_INVALID_ARGUMENT;
    out->mode = p->mode;
    if (out->mode > SG_PROXY_MODE_EXPLICIT) return SG_INVALID_ARGUMENT;
    if (out->mode != SG_PROXY_MODE_EXPLICIT) return sg::OkStatus();
    if (!SG_HAS_FIELD(p, SG_ProxyConfig, port)) return SG_INVALID_ARGUMENT;
    out->type = p->type;
    if (out->type < SG_PROXY_TYPE_HTTP_CONNECT || out->type > SG_PROXY_TYPE_SOCKS5) return SG_INVALID_ARGUMENT;
    if (!CopyCString(p->host, 253, &out->host) || out->host.empty() || p->port == 0) return SG_INVALID_ARGUMENT;
    out->port = p->port;
    if (SG_HAS_FIELD(p, SG_ProxyConfig, username) && !CopyCString(p->username, 255, &out->username)) {
        return SG_INVALID_ARGUMENT;
    }
    if (SG_HAS_FIELD(p, SG_ProxyConfig, password) && p->password != nullptr) {
        std::string pw;
        if (!CopyCString(p->password, 255, &pw)) return SG_INVALID_ARGUMENT;
        out->password.assign(pw.begin(), pw.end());
        sg::SecureZero(&pw[0], pw.size());
    }
    return sg::OkStatus();
}

Status ParseClientConfig(const SG_ClientConfig* c, sg::client::ClientSettings* s)
{
    if (c->version == 0 || !SG_HAS_FIELD(c, SG_ClientConfig, identity_name)) return SG_INVALID_ARGUMENT;
    if (!CopyCString(c->identity_name, 128, &s->identity_name)) return SG_INVALID_ARGUMENT;
    SG_TRY(sg::client::ValidateKeyName(s->identity_name));

    uint32_t key_store_type = SG_KEYSTORE_AUTO;
    std::string key_store_path;
    if (SG_HAS_FIELD(c, SG_ClientConfig, key_store_type)) key_store_type = c->key_store_type;
    if (SG_HAS_FIELD(c, SG_ClientConfig, flags)) s->flags = c->flags;
    if (SG_HAS_FIELD(c, SG_ClientConfig, key_store_path) && !CopyCString(c->key_store_path, 4096, &key_store_path)) {
        return SG_INVALID_ARGUMENT;
    }
    auto& hs = s->handshake;
    if (SG_HAS_FIELD(c, SG_ClientConfig, license_id)) {
        if (!CopyCString(c->product_id, 64, &hs.product_id) || !CopyCString(c->product_version, 32, &hs.product_version) ||
            !CopyCString(c->license_id, 128, &hs.license_id)) {
            return SG_INVALID_ARGUMENT;
        }
    }
    if (SG_HAS_FIELD(c, SG_ClientConfig, requested_features) && c->requested_features != 0) {
        hs.has_requested_features = true;
        hs.requested_features = c->requested_features;
    }
    if (SG_HAS_FIELD(c, SG_ClientConfig, client_version_patch)) {
        hs.client_version_major = c->client_version_major;
        hs.client_version_minor = c->client_version_minor;
        hs.client_version_patch = c->client_version_patch;
    }
    if (SG_HAS_FIELD(c, SG_ClientConfig, connect_timeout_ms) && c->connect_timeout_ms != 0) {
        s->connect_timeout_ms = c->connect_timeout_ms;
    }
    if (SG_HAS_FIELD(c, SG_ClientConfig, io_timeout_ms)) s->io_timeout_ms = c->io_timeout_ms;
    if (SG_HAS_FIELD(c, SG_ClientConfig, max_payload_size) && c->max_payload_size != 0) {
        if (c->max_payload_size > sg::proto::kAbsoluteMaxPayload) return SG_INVALID_ARGUMENT;
        s->max_payload = c->max_payload_size;
    }
    if (SG_HAS_FIELD(c, SG_ClientConfig, proxy)) SG_TRY(ParseProxy(c->proxy, &s->proxy));
    if (SG_HAS_FIELD(c, SG_ClientConfig, log_level)) {
        s->logger = sg::Logger(c->log_callback, c->log_user, c->log_level);
    }
    return sg::client::CreateKeyStore(key_store_type, key_store_path, &s->key_store);
}

Status ParseServerConfig(const SG_ServerConfig* c, sg::client::ServerTarget* t)
{
    if (c->version == 0 || !SG_HAS_FIELD(c, SG_ServerConfig, port)) return SG_INVALID_ARGUMENT;
    if (!CopyCString(c->host, 253, &t->host) || t->host.empty() || c->port == 0) return SG_INVALID_ARGUMENT;
    t->port = c->port;
    if (SG_HAS_FIELD(c, SG_ServerConfig, server_name) && !CopyCString(c->server_name, 253, &t->server_name)) {
        return SG_INVALID_ARGUMENT;
    }
    if (SG_HAS_FIELD(c, SG_ServerConfig, ca_file) && !CopyCString(c->ca_file, 4096, &t->ca_file)) {
        return SG_INVALID_ARGUMENT;
    }
    if (SG_HAS_FIELD(c, SG_ServerConfig, ca_pem_size) && c->ca_pem != nullptr) {
        const size_t n = c->ca_pem_size != 0 ? c->ca_pem_size : std::strlen(c->ca_pem);
        if (n > 16u * 1024 * 1024) return SG_INVALID_ARGUMENT;
        t->ca_pem.assign(c->ca_pem, n);
    }
    uint32_t flags = 0;
    if (SG_HAS_FIELD(c, SG_ServerConfig, flags)) flags = c->flags;
    t->trust_system_store = (flags & SG_TRUST_SYSTEM_STORE) != 0;
    t->allow_no_pinning = (flags & SG_SERVER_FLAG_ALLOW_NO_PINNING) != 0;
    if (SG_HAS_FIELD(c, SG_ServerConfig, spki_pins) && c->spki_pin_count != 0) {
        if (c->spki_pin_count > SG_MAX_PINS || c->spki_pins == nullptr) return SG_INVALID_ARGUMENT;
        for (uint32_t i = 0; i < c->spki_pin_count; ++i) {
            sg::crypto::Sha256Digest pin;
            std::memcpy(pin.data(), c->spki_pins[i].bytes, pin.size());
            t->spki_pins.push_back(pin);
        }
    }
    if (SG_HAS_FIELD(c, SG_ServerConfig, proof_keys) && c->proof_key_count != 0) {
        if (c->proof_key_count > SG_MAX_PROOF_KEYS || c->proof_keys == nullptr) return SG_INVALID_ARGUMENT;
        for (uint32_t i = 0; i < c->proof_key_count; ++i) {
            sg::crypto::P256PublicKey key;
            std::memcpy(key.data(), c->proof_keys[i].bytes, key.size());
            t->proof_keys.push_back(key);
        }
    }
    return sg::OkStatus();
}

void FillIdentity(const sg::client::IdentityInfo& in, SG_IdentityInfo* out)
{
    if (out == nullptr) return;
    std::memcpy(out->installation_id.bytes, in.installation_id.data(), in.installation_id.size());
    std::memcpy(out->public_key.bytes, in.public_key.data(), in.public_key.size());
    switch (in.kind) {
    case sg::client::KeyStoreKind::kMemory: out->key_store_type = SG_KEYSTORE_MEMORY; break;
    case sg::client::KeyStoreKind::kFile: out->key_store_type = SG_KEYSTORE_FILE; break;
    case sg::client::KeyStoreKind::kCngSoftware: out->key_store_type = SG_KEYSTORE_CNG_SOFTWARE; break;
    case sg::client::KeyStoreKind::kCngTpm: out->key_store_type = SG_KEYSTORE_CNG_TPM; break;
    case sg::client::KeyStoreKind::kTpm2: out->key_store_type = SG_KEYSTORE_TPM2; break;
    }
    out->hardware_backed = in.hardware_backed ? 1u : 0u;
}

uint32_t ResolveTimeout(const SG_Client* client, uint32_t timeout_ms)
{
    if (timeout_ms == SG_WAIT_INFINITE) return sg::net::kNoTimeout;
    if (timeout_ms == SG_WAIT_DEFAULT) return client->session->io_timeout_ms();
    return timeout_ms == 0 ? 1 : timeout_ms;  // 0 = poll (internally 0 means "no timeout")
}

}  // namespace

extern "C" {

SG_CLIENT_API void SG_CALL SG_ClientConfig_Init(SG_ClientConfig* config)
{
    if (config == nullptr) return;
    std::memset(config, 0, sizeof(*config));
    config->size = sizeof(*config);
    config->version = SG_CLIENT_CONFIG_VERSION;
    config->key_store_type = SG_KEYSTORE_AUTO;
    config->connect_timeout_ms = 10000;
    config->io_timeout_ms = 30000;
    config->max_payload_size = sg::proto::kDefaultMaxPayload;
    config->log_level = SG_LOG_WARN;
}

SG_CLIENT_API void SG_CALL SG_ServerConfig_Init(SG_ServerConfig* server)
{
    if (server == nullptr) return;
    std::memset(server, 0, sizeof(*server));
    server->size = sizeof(*server);
    server->version = SG_SERVER_CONFIG_VERSION;
}

SG_CLIENT_API void SG_CALL SG_ProxyConfig_Init(SG_ProxyConfig* proxy)
{
    if (proxy == nullptr) return;
    std::memset(proxy, 0, sizeof(*proxy));
    proxy->size = sizeof(*proxy);
    proxy->version = SG_PROXY_CONFIG_VERSION;
    proxy->mode = SG_PROXY_MODE_DIRECT;
}

SG_CLIENT_API void SG_CALL SG_IdentityInfo_Init(SG_IdentityInfo* info)
{
    if (info == nullptr) return;
    std::memset(info, 0, sizeof(*info));
    info->size = sizeof(*info);
    info->version = SG_IDENTITY_INFO_VERSION;
}

SG_CLIENT_API void SG_CALL SG_ClientSessionInfo_Init(SG_ClientSessionInfo* info)
{
    if (info == nullptr) return;
    std::memset(info, 0, sizeof(*info));
    info->size = sizeof(*info);
    info->version = SG_CLIENT_SESSION_INFO_VERSION;
}

SG_CLIENT_API void SG_CALL SG_MessageInfo_Init(SG_MessageInfo* info)
{
    if (info == nullptr) return;
    std::memset(info, 0, sizeof(*info));
    info->size = sizeof(*info);
    info->version = SG_MESSAGE_INFO_VERSION;
}

SG_CLIENT_API SG_Status SG_CALL SG_Client_Create(const SG_ClientConfig* config, SG_Client** client)
{
    if (config == nullptr || client == nullptr) return SG_INVALID_ARGUMENT;
    *client = nullptr;
    return Guard([&]() -> Status {
        sg::client::ClientSettings settings;
        SG_TRY(ParseClientConfig(config, &settings));
        auto handle = std::make_unique<SG_Client>();
        handle->session = std::make_unique<sg::client::ClientSession>(std::move(settings));
        *client = handle.release();
        return sg::OkStatus();
    });
}

SG_CLIENT_API SG_Status SG_CALL SG_Client_Destroy(SG_Client* client)
{
    if (client == nullptr) return SG_OK;
    return Guard([&]() -> Status {
        client->session->Disconnect();
        delete client;
        return sg::OkStatus();
    });
}

SG_CLIENT_API SG_Status SG_CALL SG_Client_EnsureIdentity(SG_Client* client, SG_IdentityInfo* info)
{
    if (client == nullptr || (info != nullptr && !SG_HAS_FIELD(info, SG_IdentityInfo, hardware_backed))) {
        return SG_INVALID_ARGUMENT;
    }
    return Guard([&]() -> Status {
        sg::client::IdentityInfo id;
        SG_TRY(client->session->EnsureIdentity(&id));
        FillIdentity(id, info);
        return sg::OkStatus();
    });
}

SG_CLIENT_API SG_Status SG_CALL SG_Client_GetIdentity(SG_Client* client, SG_IdentityInfo* info)
{
    if (client == nullptr || info == nullptr || !SG_HAS_FIELD(info, SG_IdentityInfo, hardware_backed)) {
        return SG_INVALID_ARGUMENT;
    }
    return Guard([&]() -> Status {
        sg::client::IdentityInfo id;
        SG_TRY(client->session->GetIdentity(&id));
        FillIdentity(id, info);
        return sg::OkStatus();
    });
}

SG_CLIENT_API SG_Status SG_CALL SG_Client_DeleteIdentity(SG_Client* client)
{
    if (client == nullptr) return SG_INVALID_ARGUMENT;
    return Guard([&]() { return client->session->DeleteIdentity(false); });
}

SG_CLIENT_API SG_Status SG_CALL SG_Client_DeleteIdentityEx(SG_Client* client, uint32_t flags)
{
    if (client == nullptr || (flags & ~SG_IDENTITY_DELETE_FORCE) != 0) return SG_INVALID_ARGUMENT;
    return Guard([&]() { return client->session->DeleteIdentity((flags & SG_IDENTITY_DELETE_FORCE) != 0); });
}

SG_CLIENT_API SG_Status SG_CALL SG_Client_Connect(SG_Client* client, const SG_ServerConfig* server)
{
    if (client == nullptr || server == nullptr) return SG_INVALID_ARGUMENT;
    return Guard([&]() -> Status {
        sg::client::ServerTarget target;
        SG_TRY(ParseServerConfig(server, &target));
        return client->session->Connect(target);
    });
}

SG_CLIENT_API SG_Status SG_CALL SG_Client_Authenticate(SG_Client* client)
{
    if (client == nullptr) return SG_INVALID_ARGUMENT;
    return Guard([&]() { return client->session->Authenticate(nullptr); });
}

SG_CLIENT_API SG_Status SG_CALL SG_Client_Enroll(SG_Client* client, const char* enrollment_token)
{
    if (client == nullptr || enrollment_token == nullptr) return SG_INVALID_ARGUMENT;
    return Guard([&]() -> Status {
        std::string token;
        if (!CopyCString(enrollment_token, 1024, &token) || token.empty()) return SG_INVALID_ARGUMENT;
        const Status st = client->session->Authenticate(&token);
        sg::SecureZero(&token[0], token.size());
        return st;
    });
}

SG_CLIENT_API SG_Status SG_CALL SG_Client_Refresh(SG_Client* client)
{
    if (client == nullptr) return SG_INVALID_ARGUMENT;
    return Guard([&]() { return client->session->Refresh(); });
}

SG_CLIENT_API SG_Status SG_CALL SG_Client_Disconnect(SG_Client* client)
{
    if (client == nullptr) return SG_INVALID_ARGUMENT;
    return Guard([&]() -> Status {
        client->session->Disconnect();
        return sg::OkStatus();
    });
}

SG_CLIENT_API SG_Status SG_CALL SG_Client_Send(SG_Client* client, const void* data, size_t size)
{
    return SG_Client_SendEx(client, data, size, 0, nullptr);
}

SG_CLIENT_API SG_Status SG_CALL SG_Client_SendEx(SG_Client* client, const void* data, size_t size,
                                                 uint64_t reply_to_request_id, uint64_t* out_request_id)
{
    if (client == nullptr || (data == nullptr && size != 0)) return SG_INVALID_ARGUMENT;
    return Guard([&]() {
        return client->session->Send(sg::ByteView(static_cast<const uint8_t*>(data), size), reply_to_request_id,
                                     out_request_id);
    });
}

SG_CLIENT_API SG_Status SG_CALL SG_Client_Receive(SG_Client* client, void* buffer, size_t capacity, size_t* received)
{
    return SG_Client_ReceiveEx(client, buffer, capacity, received, nullptr, SG_WAIT_DEFAULT);
}

SG_CLIENT_API SG_Status SG_CALL SG_Client_ReceiveEx(SG_Client* client, void* buffer, size_t capacity, size_t* received,
                                                    SG_MessageInfo* info, uint32_t timeout_ms)
{
    if (client == nullptr || received == nullptr || (buffer == nullptr && capacity != 0)) return SG_INVALID_ARGUMENT;
    if (info != nullptr && !SG_HAS_FIELD(info, SG_MessageInfo, flags)) return SG_INVALID_ARGUMENT;
    return Guard([&]() {
        return client->session->Receive(static_cast<uint8_t*>(buffer), capacity, received, info,
                                        ResolveTimeout(client, timeout_ms));
    });
}

SG_CLIENT_API SG_Status SG_CALL SG_Client_Ping(SG_Client* client)
{
    if (client == nullptr) return SG_INVALID_ARGUMENT;
    return Guard([&]() { return client->session->Ping(); });
}

SG_CLIENT_API SG_Status SG_CALL SG_Client_GetState(SG_Client* client, uint32_t* state)
{
    if (client == nullptr || state == nullptr) return SG_INVALID_ARGUMENT;
    *state = client->session->state();
    return SG_OK;
}

SG_CLIENT_API SG_Status SG_CALL SG_Client_GetSessionInfo(SG_Client* client, SG_ClientSessionInfo* info)
{
    if (client == nullptr || info == nullptr || !SG_HAS_FIELD(info, SG_ClientSessionInfo, tls_cipher)) {
        return SG_INVALID_ARGUMENT;
    }
    return Guard([&]() { return client->session->GetSessionInfo(info); });
}

SG_CLIENT_API uint32_t SG_CALL SG_Client_GetApiVersion(void) { return SOCKGATE_API_VERSION; }

SG_CLIENT_API SG_Status SG_CALL SG_Client_ComputeSpkiPin(const char* certificate_pem, size_t pem_size, SG_Sha256* pin)
{
    if (certificate_pem == nullptr || pin == nullptr) return SG_INVALID_ARGUMENT;
    return Guard([&]() -> Status {
        const size_t n = pem_size != 0 ? pem_size : std::strlen(certificate_pem);
        sg::crypto::Sha256Digest digest;
        SG_TRY(sg::tls::ComputeSpkiPinFromPem(sg::ByteView(reinterpret_cast<const uint8_t*>(certificate_pem), n),
                                              &digest));
        std::memcpy(pin->bytes, digest.data(), digest.size());
        return sg::OkStatus();
    });
}

}  // extern "C"
