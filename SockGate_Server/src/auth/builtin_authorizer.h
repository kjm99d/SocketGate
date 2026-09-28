#pragma once
/**
 * @file
 * @brief Built-in authorization policy with license enforcement.
 *
 *  1. The installation must be active. Registry bindings (product, license)
 *     are authoritative; a client claim that contradicts them is refused.
 *  2. The effective license is the registered one. A license id claimed by
 *     an installation without a binding is only an unverified claim, unless
 *     license activation is enabled: then a claimed license from the store
 *     activates and is pinned to the installation (first binding wins).
 *  3. A license found in the store must be active, for the session's
 *     product and unexpired. granted = requested ∩ license features (all
 *     license features when the client requested none, i.e. sent no feature
 *     request); the license expiry caps the session lifetime. Licenses
 *     unknown to the store grant nothing.
 *  4. REQUIRE_LICENSE denies every session without a verified license.
 *  5. Integrity policy: reported observations plus server-side conditions
 *     (report missing, executable not allowlisted) can deny the session or
 *     restrict it; they never raise trust.
 *  6. The application hook refines the pre-filled decision.
 *  7. Only an allowed session takes a license seat (and activates); no free
 *     seat turns the decision into a denial.
 */

#include "auth/authorizer.h"
#include "storage/client_registry.h"
#include "storage/license_store.h"

#include <functional>
#include <vector>

namespace sg::server {

/**
 * @brief Application refinement: sees the request with the license check result and may change the pre-filled
 *        decision.
 *
 * The hook runs only when the built-in rules admit the session, so it sees `allow == true`. The request carries
 * LicenseCheck, license features and integrity conditions filled by BuiltinAuthorizer. A non-OK status denies
 * the session ("application callback failed"); clearing `allow` without a reason denies it with "denied by
 * application". A RESTRICTED policy imposed by the integrity policy is re-applied after the hook, so the hook
 * cannot lift it.
 */
using AuthorizeHook = std::function<Status(const AuthorizationRequest&, AuthorizationDecision*)>;

/** @brief Integrity policy: which integrity conditions restrict or deny a session. */
struct IntegrityPolicy {
    uint32_t restrict_mask = 0;  ///< Conditions -> RESTRICTED.
    uint32_t reject_mask = 0;    ///< Conditions -> denied.
    /** SHA-256 digests of the allowed client executables; empty = no allowlist. */
    std::vector<crypto::Sha256Digest> allowed_executables;
};

/** @brief Server-side integrity condition: the client sent no integrity report (= SG_INTEGRITY_REPORT_MISSING). */
constexpr uint32_t kIntegrityReportMissing = 1u << 30;
/**
 * @brief Server-side integrity condition: an executable allowlist is configured and the reported executable hash
 *        is not in it, or no report was sent (= SG_INTEGRITY_UNKNOWN_EXECUTABLE).
 */
constexpr uint32_t kIntegrityUnknownExecutable = 1u << 31;

/**
 * @brief Computes the integrity conditions of a request: reported observations (unknown bits dropped) plus
 *        server-side conditions.
 *
 * Without a report the result is kIntegrityReportMissing, plus kIntegrityUnknownExecutable when an allowlist
 * is configured. With a report it is the reported observation flags masked to SG_INTEGRITY_KNOWN_FLAGS, plus
 * kIntegrityUnknownExecutable when an allowlist is configured and the reported executable hash is not in it.
 *
 * @warning The observation flags and the executable hash are client-reported: they can only lower trust.
 *
 * @param[in] request Request carrying the (optional) integrity report.
 * @param[in] policy  Policy providing the executable allowlist.
 * @return The condition bits.
 */
uint32_t EvaluateIntegrityConditions(const AuthorizationRequest& request, const IntegrityPolicy& policy);

/** @brief Configuration of BuiltinAuthorizer. */
struct BuiltinAuthorizerConfig {
    ILicenseStore* licenses = nullptr;   ///< Not owned; nullable: every license is then unknown.
    IClientRegistry* registry = nullptr; ///< Not owned; required for license activation (disabled when null).
    bool require_license = false;        ///< Deny every session without a verified license (REQUIRE_LICENSE).
    bool allow_activation = false;       ///< Claimed licenses may bind unbound installations.
    IntegrityPolicy integrity;           ///< Integrity policy applied to every (re)authorization.
    std::function<uint64_t()> unix_ms;   ///< Wall clock (Unix ms) for license expiry; default UnixTimeMs.
    AuthorizeHook hook;                  ///< Optional application refinement.
};

/**
 * @brief The server's built-in IAuthorizer: registry bindings, license enforcement, integrity policy and the
 *        application hook (see the file description for the rules).
 *
 * @note The configuration is fixed at construction. Authorize() may run concurrently; it relies on the
 *       thread safety of the configured stores and hook. The stores must outlive the authorizer.
 */
class BuiltinAuthorizer final : public IAuthorizer {
public:
    /**
     * @brief Creates the authorizer.
     * @param[in] config Configuration (moved in).
     */
    explicit BuiltinAuthorizer(BuiltinAuthorizerConfig config) : config_(std::move(config)) {}

    /**
     * @brief Applies the built-in rules, runs the hook and, for an allowed session with a verified license,
     *        takes the seat (and pins an activated license).
     *
     * @p decision is reset first. Denials are reported through `decision->allow == false` with a log-only
     * `deny_reason` (e.g. contradicting claims, revoked, foreign-product or expired license, missing required
     * license, integrity rejection, application denial, license store failure, no free seat, failed
     * activation); `granted_features` is then 0. For an allowed session with a verified license,
     * `license_verified` is set and `seat_newly_taken` tells whether this call took the seat.
     *
     * @param[in]  request  Verified identity and client claims.
     * @param[out] decision Receives the decision.
     * @retval SG_OK               A decision (allow or deny) was made.
     * @retval SG_INVALID_ARGUMENT @p decision is null.
     */
    Status Authorize(const AuthorizationRequest& request, AuthorizationDecision* decision) override;

private:
    /** @brief Current wall-clock time. @return Unix ms from config_.unix_ms if set, else UnixTimeMs(). */
    uint64_t Now() const;

    /**
     * @brief Takes the seat (and pins an activated license) for an allowed session.
     *
     * SG_LIMIT_EXCEEDED from the store (a full license, or a store file that would grow beyond
     * kMaxStorageFileSize) denies with "license installation limit reached", any other seat binding failure
     * with "license seat binding failed". If pinning an activated license fails, the session is denied and a seat
     * this call took is given back, except after a storage error (the seat stays; the next attempt pins).
     *
     * @param[in]     request    The request being authorized.
     * @param[in]     license_id Verified license to bind.
     * @param[in]     product_id Product of that license (pinned with it on activation).
     * @param[in]     activate   True to pin the license to the installation in the registry.
     * @param[in,out] decision   Allowed decision; turned into a denial on failure, `seat_newly_taken` set on
     *                           success.
     * @retval SG_OK Always; failures are reported as denials in @p decision.
     */
    Status Commit(const AuthorizationRequest& request, const std::string& license_id, const std::string& product_id,
                  bool activate, AuthorizationDecision* decision);

    BuiltinAuthorizerConfig config_;  ///< Immutable configuration.
};

}  // namespace sg::server
