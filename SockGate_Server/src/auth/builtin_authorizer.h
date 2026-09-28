// Built-in authorization policy with license enforcement.
//
//  1. The installation must be active. Registry bindings (product, license)
//     are authoritative; a client claim that contradicts them is refused.
//  2. The effective license is the registered one. A license id claimed by
//     an installation without a binding is only an unverified claim, unless
//     license activation is enabled: then a claimed license from the store
//     activates and is pinned to the installation (first binding wins).
//  3. A license found in the store must be active, for the session's
//     product and unexpired. granted = requested ∩ license features (all
//     license features when the client requested none); the license expiry
//     caps the session lifetime. Licenses unknown to the store grant nothing.
//  4. REQUIRE_LICENSE denies every session without a verified license.
//  5. Integrity policy: reported observations plus server-side conditions
//     (report missing, executable not allowlisted) can deny the session or
//     restrict it; they never raise trust.
//  6. The application hook refines the pre-filled decision.
//  7. Only an allowed session takes a license seat (and activates); no free
//     seat turns the decision into a denial.
#pragma once

#include "auth/authorizer.h"
#include "storage/client_registry.h"
#include "storage/license_store.h"

#include <functional>
#include <vector>

namespace sg::server {

// Application refinement: sees the request with the license check result
// and may change the pre-filled decision.
using AuthorizeHook = std::function<Status(const AuthorizationRequest&, AuthorizationDecision*)>;

struct IntegrityPolicy {
    uint32_t restrict_mask = 0;  // conditions -> RESTRICTED
    uint32_t reject_mask = 0;    // conditions -> denied
    std::vector<crypto::Sha256Digest> allowed_executables;  // empty = no allowlist
};

// Server-side integrity conditions (same bits as the public SG_INTEGRITY_*).
constexpr uint32_t kIntegrityReportMissing = 1u << 30;
constexpr uint32_t kIntegrityUnknownExecutable = 1u << 31;

// Reported observations (unknown bits dropped) plus server-side conditions.
uint32_t EvaluateIntegrityConditions(const AuthorizationRequest& request, const IntegrityPolicy& policy);

struct BuiltinAuthorizerConfig {
    ILicenseStore* licenses = nullptr;   // nullable: every license is then unknown
    IClientRegistry* registry = nullptr; // required for license activation
    bool require_license = false;
    bool allow_activation = false;       // claimed licenses may bind unbound installations
    IntegrityPolicy integrity;
    std::function<uint64_t()> unix_ms;   // wall clock; default UnixTimeMs
    AuthorizeHook hook;                  // optional
};

class BuiltinAuthorizer final : public IAuthorizer {
public:
    explicit BuiltinAuthorizer(BuiltinAuthorizerConfig config) : config_(std::move(config)) {}

    Status Authorize(const AuthorizationRequest& request, AuthorizationDecision* decision) override;

private:
    uint64_t Now() const;
    // Takes the seat (and pins an activated license) for an allowed session.
    Status Commit(const AuthorizationRequest& request, const std::string& license_id, const std::string& product_id,
                  bool activate, AuthorizationDecision* decision);

    BuiltinAuthorizerConfig config_;
};

}  // namespace sg::server
