#pragma once
/**
 * @file
 * @brief Authorization: the server's final decision about an authenticated client.
 *
 * Everything in AuthorizationRequest that came from the client is a *claim* (product, license, requested
 * features, integrity report). Only the installation record (looked up by the verified key) is server-trusted.
 */

#include "storage/client_registry.h"

#include "sockgate_common/protocol/messages.h"

#include <string>

namespace sg::server {

/**
 * @brief Result of the built-in license check (server-verified, not a claim).
 *
 * Set by BuiltinAuthorizer in AuthorizationRequest::license_status before the application hook runs, and
 * reported in SessionSnapshot::license_status for open sessions.
 */
enum class LicenseCheck : uint8_t {
    /**
     * No license bound or claimed. In a SessionSnapshot also for a session whose license was only claimed and
     * not verified: snapshots report registered or verified licenses only.
     */
    kNone = 0,
    /**
     * Verified against the license store: active, for the session's product and unexpired. In a
     * SessionSnapshot the installation's seat is bound. In the AuthorizationRequest seen by the application
     * hook the seat is not taken yet: BuiltinAuthorizer binds it only after the hook allowed the session, and
     * a full license still turns the decision into a denial.
     */
    kValid = 1,
    /**
     * Unverified. Claimed or bound, but not in the license store; in the request seen by the hook also a
     * license claimed by an installation without a license binding while license activation is off (that
     * claim is not looked up at all). In a SessionSnapshot only a registered license binding that the store
     * does not know. Grants nothing by itself.
     */
    kUnknown = 2,
};

/**
 * @brief Input of IAuthorizer::Authorize for one (re)authentication.
 *
 * Built by the handshake after the client proved possession of its key (or enrolled), and again for every
 * reauthentication. The fields below "Client claims" come from the client's CLIENT_HELLO and are never
 * trusted by themselves.
 *
 * @warning Only the identity (#installation_id, #record) is verified, and the fields filled by the built-in
 *          authorizer are computed by the server. Product, license, requested features, client version and
 *          integrity report are client claims.
 */
struct AuthorizationRequest {
    proto::InstallationId installation_id{};  ///< Verified installation id (its key signed the transcript).
    /** Verified registry entry; points to a caller-owned copy that is valid only during the Authorize() call. */
    const ClientRecord* record = nullptr;
    proto::AuthMode mode = proto::AuthMode::kAuthenticate;  ///< Authentication mode requested in CLIENT_HELLO.
    bool reauthentication = false;  ///< True when called for a reauthentication of an open session.
    uint64_t session_handle = 0;    ///< Handle of the connection being authorized.
    // Client claims:
    std::string product_id;       ///< Claimed product id (may be empty).
    std::string product_version;  ///< Claimed product version (may be empty).
    std::string license_id;       ///< Claimed license id (may be empty).
    bool has_requested_features = false;  ///< True if the client sent a feature request.
    uint64_t requested_features = 0;      ///< Requested feature bits (meaningful if #has_requested_features).
    uint16_t client_version_major = 0;    ///< Claimed client library version, major part.
    uint16_t client_version_minor = 0;    ///< Claimed client library version, minor part.
    uint16_t client_version_patch = 0;    ///< Claimed client library version, patch part.
    bool has_integrity = false;           ///< True if the client sent an integrity report.
    proto::IntegrityReport integrity;     ///< Client-reported integrity observations (meaningful if #has_integrity).
    /** Peer address of the connection as reported by the accepted socket (not authenticated). */
    std::string peer_address;
    // Filled by the built-in authorizer before the application hook runs:
    LicenseCheck license_status = LicenseCheck::kNone;  ///< Result of the server-side license check.
    uint64_t license_features = 0;  ///< Entitlement of a verified license (0 unless #license_status is kValid).
    uint32_t integrity_conditions = 0;  ///< Reported flags + server-side conditions (see EvaluateIntegrityConditions).
};

/**
 * @brief Output of IAuthorizer::Authorize: whether and how the session may run.
 *
 * The handshake accepts an allowed decision only with policy kNormal or kRestricted. The effective session
 * lifetime is #session_lifetime_ms (or the server default), capped by the configured maximum and by the time
 * left until #license_expires_at_ms; a license that already expired rejects the session.
 */
struct AuthorizationDecision {
    bool allow = false;  ///< True to admit the session.
    proto::SessionPolicy policy = proto::SessionPolicy::kNormal;  ///< Policy reported to the client.
    uint64_t granted_features = 0;       ///< Feature bits granted to the session.
    uint32_t session_lifetime_ms = 0;    ///< Requested session lifetime; 0 = server default.
    uint64_t license_expires_at_ms = 0;  ///< Unix ms of the license expiry; 0 = not license bound (or no expiry).
    std::string license_id;              ///< License the session was authorised under (for revocation).
    bool license_verified = false;       ///< #license_id was checked against the license store.
    bool seat_newly_taken = false;       ///< This authorization took the license seat.
    std::string deny_reason;             ///< For server logs only, never sent to the client.
};

/**
 * @brief Server-side authorization policy.
 *
 * @note Authorize() is called concurrently from I/O worker threads (one call per handshake or
 *       reauthentication) and without any connection lock held; implementations must be thread-safe.
 */
class IAuthorizer {
public:
    virtual ~IAuthorizer() = default;

    /**
     * @brief Decides whether an authenticated client may open (or keep) a session.
     *
     * Fills @p decision. A non-OK status is treated as a denial.
     *
     * @param[in]  request  Verified identity and client claims.
     * @param[out] decision Receives the decision.
     * @retval SG_OK The decision was filled; `decision->allow` tells whether the session is admitted.
     */
    virtual Status Authorize(const AuthorizationRequest& request, AuthorizationDecision* decision) = 0;
};

/**
 * @brief Allows every verified installation with NORMAL policy and no features.
 *
 * Denies (with deny_reason "installation not active") when the record is missing or not active. It sets only
 * `allow`, `policy`, `granted_features` and, on denial, `deny_reason`; it does no license checks.
 */
class AllowRegisteredAuthorizer final : public IAuthorizer {
public:
    /**
     * @brief Allows the request if its installation record is active.
     * @param[in]  request  Request to evaluate.
     * @param[out] decision Receives the decision; must not be null.
     * @retval SG_OK Always.
     */
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
