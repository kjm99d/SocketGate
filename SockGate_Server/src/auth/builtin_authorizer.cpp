#include "auth/builtin_authorizer.h"

#include "sockgate_common/core/clock.h"

#include <sockgate/types.h>

#include <algorithm>
#include <cstdio>

namespace sg::server {
namespace {

Status Deny(AuthorizationDecision* decision, const char* reason)
{
    decision->allow = false;
    decision->granted_features = 0;
    decision->deny_reason = reason;
    return OkStatus();
}

}  // namespace

uint32_t EvaluateIntegrityConditions(const AuthorizationRequest& request, const IntegrityPolicy& policy)
{
    if (!request.has_integrity) {
        return kIntegrityReportMissing | (policy.allowed_executables.empty() ? 0u : kIntegrityUnknownExecutable);
    }
    uint32_t conditions = request.integrity.observation_flags & SG_INTEGRITY_KNOWN_FLAGS;
    if (!policy.allowed_executables.empty() &&
        std::find(policy.allowed_executables.begin(), policy.allowed_executables.end(),
                  request.integrity.executable_sha256) == policy.allowed_executables.end()) {
        conditions |= kIntegrityUnknownExecutable;
    }
    return conditions;
}

uint64_t BuiltinAuthorizer::Now() const { return config_.unix_ms ? config_.unix_ms() : UnixTimeMs(); }

Status BuiltinAuthorizer::Authorize(const AuthorizationRequest& request, AuthorizationDecision* decision)
{
    if (decision == nullptr) return SG_INVALID_ARGUMENT;
    *decision = AuthorizationDecision();
    decision->policy = proto::SessionPolicy::kNormal;

    const ClientRecord* record = request.record;
    if (record == nullptr || record->status != ClientStatus::kActive) return Deny(decision, "installation not active");
    if (!record->product_id.empty() && !request.product_id.empty() && record->product_id != request.product_id) {
        return Deny(decision, "product claim contradicts registration");
    }
    if (!record->license_id.empty() && !request.license_id.empty() && record->license_id != request.license_id) {
        return Deny(decision, "license claim contradicts registration");
    }
    const std::string& product = record->product_id.empty() ? request.product_id : record->product_id;

    // Which license (if any) is looked up in the store.
    std::string license_id;
    bool activate = false;
    AuthorizationRequest checked = request;
    if (!record->license_id.empty()) {
        license_id = record->license_id;
        decision->license_id = license_id;  // registry-trusted even if the store does not know it
    } else if (!request.license_id.empty()) {
        if (config_.allow_activation && config_.registry != nullptr) {
            license_id = request.license_id;
            activate = true;
        } else {
            checked.license_status = LicenseCheck::kUnknown;  // an unverified claim
        }
    }

    LicenseRecord license;
    if (!license_id.empty()) {
        const Status found = config_.licenses != nullptr ? config_.licenses->Find(license_id, &license)
                                                         : Status(SG_NOT_FOUND);
        if (found == SG_NOT_FOUND) {
            checked.license_status = LicenseCheck::kUnknown;
            activate = false;  // nothing to activate
        } else if (!found.ok()) {
            return Deny(decision, "license store failure");
        } else {
            if (license.status != LicenseStatus::kActive) return Deny(decision, "license revoked");
            if (license.product_id != product) return Deny(decision, "license is for another product");
            if (license.expires_at_ms != 0 && license.expires_at_ms <= Now()) return Deny(decision, "license expired");
            checked.license_status = LicenseCheck::kValid;
            checked.license_features = license.features;
            decision->license_id = license_id;
            decision->license_verified = true;
            decision->license_expires_at_ms = license.expires_at_ms;
            decision->granted_features =
                request.has_requested_features ? request.requested_features & license.features : license.features;
        }
    }
    if (config_.require_license && checked.license_status != LicenseCheck::kValid) {
        return Deny(decision, !request.license_id.empty() && record->license_id.empty()
                                  ? "license claim not bound to installation"
                                  : "valid license required");
    }

    // Integrity reports only ever lower trust.
    checked.integrity_conditions = EvaluateIntegrityConditions(request, config_.integrity);
    const uint32_t rejected = checked.integrity_conditions & config_.integrity.reject_mask;
    if (rejected != 0) {
        Deny(decision, "integrity policy").IgnoreError();
        char detail[48];
        std::snprintf(detail, sizeof(detail), " (conditions 0x%08x)", rejected);
        decision->deny_reason += detail;
        return OkStatus();
    }
    const bool restricted_by_integrity = (checked.integrity_conditions & config_.integrity.restrict_mask) != 0;
    if (restricted_by_integrity) decision->policy = proto::SessionPolicy::kRestricted;

    decision->allow = true;
    if (config_.hook) {
        const Status st = config_.hook(checked, decision);
        if (!st.ok()) {
            decision->allow = false;
            decision->deny_reason = "application callback failed";
        } else if (!decision->allow && decision->deny_reason.empty()) {
            decision->deny_reason = "denied by application";
        }
    }
    if (!decision->allow) {
        decision->granted_features = 0;
        return OkStatus();
    }
    // Integrity only ever lowers trust: the hook cannot lift the floor.
    if (restricted_by_integrity) decision->policy = proto::SessionPolicy::kRestricted;
    if (decision->license_verified) return Commit(request, license_id, license.product_id, activate, decision);
    return OkStatus();
}

Status BuiltinAuthorizer::Commit(const AuthorizationRequest& request, const std::string& license_id,
                                 const std::string& product_id, bool activate, AuthorizationDecision* decision)
{
    bool seat_taken = false;
    const Status bound = config_.licenses->BindSeat(license_id, request.installation_id, &seat_taken);
    if (bound == SG_LIMIT_EXCEEDED) return Deny(decision, "license installation limit reached");
    if (!bound.ok()) return Deny(decision, "license seat binding failed");
    if (activate) {
        const Status pinned = config_.registry->BindLicense(request.installation_id, product_id, license_id);
        if (!pinned.ok()) {
            // Bound to another license or revoked meanwhile: no session of
            // this installation can use this seat, so give back the one this
            // call took. After an I/O failure the seat stays (the next attempt pins).
            if (seat_taken && pinned != SG_STORAGE_ERROR) {
                config_.licenses->ReleaseSeat(license_id, request.installation_id).IgnoreError();
            }
            return Deny(decision, "license activation failed");
        }
    }
    decision->seat_newly_taken = seat_taken;
    return OkStatus();
}

}  // namespace sg::server
