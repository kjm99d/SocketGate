// Authorization: the server's final decision about an authenticated client.
//
// Everything in AuthorizationRequest that came from the client is a *claim*
// (product, license, requested features, integrity report). Only the
// installation record (looked up by the verified key) is server-trusted.
#pragma once

#include "storage/client_registry.h"

#include "sockgate_common/protocol/messages.h"

#include <string>

namespace sg::server {

struct AuthorizationRequest {
    proto::InstallationId installation_id{};
    const ClientRecord* record = nullptr;  // verified registry entry
    proto::AuthMode mode = proto::AuthMode::kAuthenticate;
    bool reauthentication = false;
    // Client claims:
    std::string product_id;
    std::string product_version;
    std::string license_id;
    bool has_requested_features = false;
    uint64_t requested_features = 0;
    uint16_t client_version_major = 0;
    uint16_t client_version_minor = 0;
    uint16_t client_version_patch = 0;
    bool has_integrity = false;
    proto::IntegrityReport integrity;
    std::string peer_address;
};

struct AuthorizationDecision {
    bool allow = false;
    proto::SessionPolicy policy = proto::SessionPolicy::kNormal;
    uint64_t granted_features = 0;
    uint32_t session_lifetime_ms = 0;  // 0 = server default
    uint64_t license_expires_at_ms = 0;  // 0 = not license bound
    std::string license_id;  // license the session was authorised under (for revocation)
    std::string deny_reason;  // for server logs only, never sent to the client
};

class IAuthorizer {
public:
    virtual ~IAuthorizer() = default;
    // Fills `decision`. A non-OK status is treated as a denial.
    virtual Status Authorize(const AuthorizationRequest& request, AuthorizationDecision* decision) = 0;
};

// Allows every verified installation with NORMAL policy and no features.
class AllowRegisteredAuthorizer final : public IAuthorizer {
public:
    Status Authorize(const AuthorizationRequest& request, AuthorizationDecision* decision) override
    {
        decision->allow = request.record != nullptr && request.record->status == ClientStatus::kActive;
        decision->policy = proto::SessionPolicy::kNormal;
        decision->granted_features = 0;
        if (!decision->allow) decision->deny_reason = "installation not active";
        return OkStatus();
    }
};

}  // namespace sg::server
