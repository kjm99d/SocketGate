#pragma once
/**
 * @file
 * @brief ServerEngine: accept loop, connection/session management, sweeper and the bridge to application
 *        callbacks.
 *
 * Lock order: engine mutexes are never acquired while a Connection's mutex
 * is held; connections report back through events delivered outside it.
 * In full: lifecycle_mutex_ may be held while connection mutexes and
 * connections_mutex_ are taken (Stop() closes every connection, which may
 * deliver its events on the stopping thread); a Connection's mutex and
 * connections_mutex_ may be held while the registry, the license store and
 * the I/O streams take their internal mutexes (leaf locks).
 */

#include "auth/authorizer.h"
#include "auth/builtin_authorizer.h"
#include "auth/server_handshake.h"
#include "storage/client_registry.h"
#include "storage/license_store.h"
#include "transport/io_service.h"

#include "sockgate_common/core/log.h"
#include "sockgate_common/tls/tls.h"

#include <sockgate/types.h>

#include <atomic>
#include <condition_variable>
#include <functional>
#include <map>
#include <memory>
#include <mutex>
#include <string>
#include <thread>
#include <vector>

namespace sg::server {

class Connection;

/** @brief Point-in-time view of an open session (SG_Server_GetSessionInfo and the session-opened callback). */
struct SessionSnapshot {
    SG_SessionHandle handle = SG_INVALID_SESSION_HANDLE;  ///< Session handle.
    proto::SessionId session_id{};                        ///< Protocol session id.
    proto::InstallationId installation_id{};              ///< Verified installation id.
    proto::SessionPolicy policy = proto::SessionPolicy::kNone;  ///< Current session policy.
    uint32_t epoch = 0;                    ///< Key epoch: 0 after the handshake, +1 per reauthentication.
    uint64_t granted_features = 0;         ///< Features granted by the current authorization.
    uint64_t license_expires_at_ms = 0;    ///< Unix ms of the license expiry; 0 = none (or not license bound).
    /**
     * kValid for a verified license, kUnknown for a registered license the store does not know, kNone otherwise
     * (also when the client only claimed a license).
     */
    LicenseCheck license_status = LicenseCheck::kNone;
    uint64_t expires_in_ms = 0;            ///< Remaining session lifetime at snapshot time.
    bool enrolled = false;                 ///< The session's handshake enrolled the installation.
    std::string peer_address;              ///< Peer address of the connection.
    /**
     * Registered product id, or the client's claimed product id when the installation has no product binding.
     * @warning In the latter case this is an unverified client claim.
     */
    std::string product_id;
    /** Registered or verified license only; never a raw client claim. Empty if none. */
    std::string license_id;
};

/**
 * @brief Application callbacks the engine invokes.
 *
 * Every callback is optional. Session events (#session_opened, #message, #session_closed) of one connection
 * are delivered serially and in order, outside the connection lock, by whichever thread finds the event queue
 * non-empty: an I/O worker, the sweeper, or an application thread whose call closed the session (e.g.
 * CloseSession(), Send(), a revocation or Stop()). The engine marks #authorize, #session_opened, #message and
 * #session_closed with a CallbackScope; #enroll is passed to the handshake unchanged. Exceptions thrown by
 * session callbacks are swallowed.
 */
struct EngineCallbacks {
    /**
     * App authorisation hook; `decision` is pre-filled with the built-in result. Called for the handshake and
     * every reauthentication, only when the built-in rules admit the session, without any connection lock
     * held. A non-OK status denies the session (see AuthorizeHook).
     */
    std::function<Status(SG_SessionHandle, const AuthorizationRequest&, AuthorizationDecision*)> authorize;
    EnrollValidator enroll;  ///< External enrollment validator; replaces built-in token validation when set.
    std::function<void(const SessionSnapshot&)> session_opened;  ///< A session was authenticated and opened.
    /** A DATA message arrived; the data is valid only during the call. `flags` holds SG_MESSAGE_FLAG_* bits. */
    std::function<void(SG_SessionHandle, const uint8_t*, size_t, uint64_t request_id, uint32_t flags)> message;
    /** An opened session closed, with the public status of the reason. Not called for unopened connections. */
    std::function<void(SG_SessionHandle, SG_Status)> session_closed;
};

/** @brief Configuration of a ServerEngine (validated by ServerEngine::Create()). */
struct EngineConfig {
    std::string bind_address = "0.0.0.0";  ///< Address to listen on.
    uint16_t port = 0;                     ///< Port to listen on; 0 = chosen by the OS (see ServerEngine::port()).
    /** TLS settings; the private key PEM is wiped and cleared once loaded into the TLS context. */
    tls::TlsServerConfig tls;
    /**
     * Handshake settings. An empty token key is replaced by a random one (tokens are then valid for this server
     * instance only); EngineCallbacks::enroll, when set, replaces the enroll_validator.
     */
    HandshakeConfig handshake;
    std::string registry_path;  ///< Installation registry file; empty = in-memory registry (not persisted).
    std::string license_path;   ///< License store file; empty = in-memory store (not persisted).
    bool require_license = false;           ///< Deny sessions without a verified license.
    bool allow_license_activation = false;  ///< Claimed licenses may bind unbound installations.
    IntegrityPolicy integrity;              ///< Integrity policy of the built-in authorizer.
    uint32_t worker_threads = 0;       ///< I/O worker threads (at most 64); 0 = hardware concurrency.
    /** Limit of accepted connections, including streams in their graceful-close phase; non-zero. */
    uint32_t max_connections = 10'000;
    uint32_t max_unauthenticated = 0;  ///< 0 = max_connections / 2, at least 1; must not exceed max_connections.
    uint32_t handshake_timeout_ms = 15'000;  ///< Time from accept to authentication; non-zero.
    uint32_t idle_timeout_ms = 300'000;      ///< Close a session that received no frame for this long; 0 = off.
    uint32_t max_payload = 1u << 20;         ///< Maximum DATA payload in bytes; 1..proto::kAbsoluteMaxPayload.
    /** Minimum time since session open or the last reauthentication request; an earlier one is a protocol error. */
    uint32_t min_reauth_interval_ms = 10'000;
    /** DATA frames from the client must be encrypted (others are a protocol error); replies are encrypted. */
    bool require_app_encryption = false;
    /** Log sink. Invoked while engine or connection locks may be held: it must not call the server API. */
    Logger logger;
};

/**
 * @brief Server counters. Each counter is atomic on its own; they are not updated as one consistent snapshot.
 */
struct EngineStats {
    std::atomic<uint64_t> active_sessions{0};    ///< Currently open sessions.
    std::atomic<uint64_t> total_connections{0};  ///< Connections admitted since creation.
    std::atomic<uint64_t> auth_succeeded{0};     ///< Successful handshakes.
    /**
     * Handshakes and reauthentications answered with REJECTED. Version mismatches, handshake timeouts and
     * reauthentication challenges that expire unanswered are not counted.
     */
    std::atomic<uint64_t> auth_failed{0};
    std::atomic<uint64_t> protocol_errors{0};    ///< Closes because processing received data failed (not SG_CLOSED).
    std::atomic<uint64_t> messages_received{0};  ///< DATA messages queued for delivery.
    std::atomic<uint64_t> messages_sent{0};      ///< DATA messages sent by Send().
};

/**
 * @brief The server core: owns the stores, the authorizer, the TLS context, the I/O service, every connection
 *        and the sweeper thread.
 *
 * Invariants: every admitted connection is in `connections_` until its close is delivered (OnConnectionClosed());
 * a stream whose connection closed stays in `closing_` until it closed or the graceful-close timeout (5 s) forced
 * it shut. Both count against max_connections. A connection that has not authenticated holds one place in
 * `unauthenticated_` from accept until it authenticates or its stream is gone.
 *
 * @note The session, administration and statistics methods are thread-safe and may be called from application
 *       callbacks. Start() and Stop() must not be: Stop() may deliver close events (application callbacks) on
 *       the calling thread while holding the lifecycle lock, so the public API refuses Start/Stop/Destroy from
 *       inside a callback (see InApplicationCallback()).
 */
class ServerEngine {
public:
    /**
     * @brief Validates the configuration and creates an engine (not yet listening).
     *
     * Creates the TLS context (and wipes the private key PEM), opens the registry and license store (file
     * backed if a path is set, locked for exclusive use), builds the BuiltinAuthorizer with the authorize hook
     * and the handshake context. Logs a warning if the executable allowlist has no effect.
     *
     * @param[in]  config    Configuration (moved in).
     * @param[in]  callbacks Application callbacks (moved in).
     * @param[out] out       Receives the engine.
     * @retval SG_OK               Created.
     * @retval SG_INVALID_ARGUMENT @p out is null, an invalid limit (max_payload, max_connections,
     *                             handshake_timeout_ms, max_unauthenticated) or handshake setting, or an unusable
     *                             store path.
     * @retval SG_INVALID_STATE    A registry or license store file is in use by another holder.
     * @retval SG_STORAGE_ERROR    A store file cannot be read or is malformed.
     * @retval other               TLS context creation or key generation failures.
     */
    static Status Create(EngineConfig config, EngineCallbacks callbacks, std::unique_ptr<ServerEngine>* out);
    /** @brief Stops the engine (see Stop()). */
    ~ServerEngine();

    ServerEngine(const ServerEngine&) = delete;
    ServerEngine& operator=(const ServerEngine&) = delete;

    /**
     * @brief Starts the I/O service, listens and starts the sweeper.
     * @retval SG_OK            Listening; port() reports the bound port.
     * @retval SG_INVALID_STATE Already running.
     * @retval other            I/O service start or listen failure (logged).
     */
    Status Start();
    /**
     * @brief Stops the engine. Idempotent; no-op when not running.
     *
     * Closes every connection (authenticated peers receive CLOSE(SERVER_SHUTDOWN)), waits up to about 500 ms
     * for the streams to flush, stops the sweeper and the I/O service, and releases every connection.
     *
     * @note Close events may be delivered to the application on the calling thread while the lifecycle lock is
     *       held. Must not be called from an application callback.
     */
    void Stop() noexcept;
    /** @brief Bound listening port. @return The port; 0 before the first successful Start(). */
    uint16_t port() const noexcept { return port_; }

    /**
     * @brief Sends a DATA message on an open session.
     * @param[in] session             Session handle.
     * @param[in] data                Payload; at most max_payload bytes. Copied before returning.
     * @param[in] reply_to_request_id Request id to answer (marks a response), or 0 for a new request id.
     * @retval SG_OK               Queued for transmission.
     * @retval SG_NOT_FOUND        Unknown handle.
     * @retval SG_CLOSED           The session is closing, not yet authenticated, or failed while sending (it
     *                             is closed then).
     * @retval SG_INVALID_ARGUMENT Payload too large, or a reply to an unknown request id.
     * @retval SG_LIMIT_EXCEEDED   The peer does not read: too much output is pending.
     */
    Status Send(SG_SessionHandle session, ByteView data, uint64_t reply_to_request_id);
    /**
     * @brief Gracefully closes a connection; an authenticated peer receives CLOSE(NORMAL).
     * @param[in] session Session handle.
     * @retval SG_OK        Closing (also if it already was).
     * @retval SG_NOT_FOUND Unknown handle.
     */
    Status CloseSession(SG_SessionHandle session);
    /**
     * @brief Takes a snapshot of an open session.
     * @param[in]  session Session handle.
     * @param[out] out     Receives the snapshot.
     * @retval SG_OK        Filled.
     * @retval SG_NOT_FOUND Unknown handle, or the session is not (or no longer) open.
     */
    Status GetSession(SG_SessionHandle session, SessionSnapshot* out);

    /**
     * @brief Registers an installation (administrator action).
     *
     * A license binding must be consistent (see CheckLicenseBinding()). `created_at_ms` 0 is replaced by the
     * current time.
     *
     * @param[in] record Record to register.
     * @retval SG_OK               Registered (durable for a file registry).
     * @retval SG_ALREADY_EXISTS   The installation id is known (active or revoked).
     * @retval SG_INVALID_ARGUMENT Invalid record, or a bound license for another product.
     * @retval SG_INVALID_STATE    The bound license is revoked.
     * @retval SG_NOT_FOUND        The bound license is unknown while licenses are required.
     * @retval other               Store failures (the registration is rolled back).
     */
    Status RegisterClient(const ClientRecord& record);
    /**
     * @brief Revokes an installation; takes effect immediately for live sessions.
     *
     * Bumps the revocation generation, closes every open session of the installation (CLOSE(AUTH_FAILED),
     * reported as SG_AUTH_FAILED) and releases its seat on its registered license (best effort): a revoked
     * installation can never use that seat again.
     *
     * @param[in] installation_id Installation to revoke.
     * @retval SG_OK            Revoked and persisted.
     * @retval SG_STORAGE_ERROR Revoked in memory but not persisted. The revocation still takes effect for this
     *                          process; the caller learns it is not durable.
     * @retval SG_NOT_FOUND     Unknown installation (nothing changed).
     */
    Status RevokeClient(const proto::InstallationId& installation_id);
    /**
     * @brief Issues a built-in enrollment token for a product (and optionally a license binding).
     *
     * @warning The token string contains K_tok: it is a bearer secret until redeemed. Redeeming it consumes its
     *          token id in the registry: single use per registry, and an in-memory registry forgets consumed
     *          tokens on restart. It is valid only for servers using the same token key (without a configured
     *          key: this instance only).
     *
     * @param[in]  product_id Product the enrolled installation is bound to; required.
     * @param[in]  license_id License to bind, or empty (see CheckLicenseBinding()).
     * @param[in]  ttl_ms     Validity; 0 = 24 hours; at most proto::kMaxEnrollmentTokenLifetimeMs.
     * @param[out] token      Receives the token string.
     * @retval SG_OK               Issued.
     * @retval SG_INVALID_ARGUMENT @p token is null, @p product_id is empty, @p ttl_ms is too long, or the
     *                             license is for another product.
     * @retval SG_INVALID_STATE    The license is revoked.
     * @retval SG_NOT_FOUND        The license is unknown while licenses are required.
     * @retval other               Store or token encoding failures.
     */
    Status IssueEnrollmentToken(const std::string& product_id, const std::string& license_id, uint32_t ttl_ms,
                                std::string* token);

    /**
     * @brief Adds a license or updates its terms, keeping existing seats.
     *
     * Changed terms apply to new sessions and at each session's next refresh.
     *
     * @param[in] record License terms (`status` and `seats_used` are ignored).
     * @retval SG_OK               Stored.
     * @retval SG_INVALID_ARGUMENT Invalid identifiers.
     * @retval SG_INVALID_STATE    The license is revoked (revocation is permanent).
     * @retval SG_LIMIT_EXCEEDED   kMaxLicenses reached, or the store file would become too large.
     * @retval other               Store failures (the change is rolled back).
     */
    Status AddLicense(const LicenseRecord& record);
    /**
     * @brief Revokes a license (permanently) and closes every open session authorised under it.
     *
     * Bumps the revocation generation. Seats bound to the license are kept.
     *
     * @param[in] license_id License to revoke.
     * @retval SG_OK            Revoked and persisted.
     * @retval SG_STORAGE_ERROR Revoked in memory but not persisted. The revocation still takes effect for this
     *                          process; the caller learns it is not durable.
     * @retval SG_NOT_FOUND     Unknown license (nothing changed).
     */
    Status RevokeLicense(const std::string& license_id);
    /**
     * @brief Frees an installation's seat on a license and closes that installation's sessions under it.
     *
     * Bumps the revocation generation. The installation may take a seat again on its next authentication if
     * one is free.
     *
     * @param[in] license_id      License.
     * @param[in] installation_id Installation holding the seat.
     * @retval SG_OK        Released.
     * @retval SG_NOT_FOUND Unknown license, or the installation holds no seat on it.
     * @retval other        Store failure (the seat is kept).
     */
    Status ReleaseLicenseSeat(const std::string& license_id, const proto::InstallationId& installation_id);
    /**
     * @brief Looks up a license, including its current seat count.
     * @param[in]  license_id License id.
     * @param[out] out        Receives the record.
     * @retval SG_OK               Found.
     * @retval SG_NOT_FOUND        Unknown license.
     * @retval SG_INVALID_ARGUMENT @p out is null.
     */
    Status GetLicense(const std::string& license_id, LicenseRecord* out);

    /**
     * @brief Number of tracked connections.
     * @return Accepted connections, authenticated or not, that did not finish closing (graceful-close streams
     *         excluded).
     */
    uint64_t ActiveConnections();
    /** @brief Number of open sessions. @return EngineStats::active_sessions. */
    uint64_t ActiveSessions();
    /** @brief Server counters. @return The counters. */
    const EngineStats& stats() const noexcept { return stats_; }

    // ---- used by Connection ----------------------------------------------------
    /** @brief Effective configuration. @return The configuration (TLS private key already wiped). */
    const EngineConfig& config() const noexcept { return config_; }
    /** @brief Log sink. @return The logger. */
    const Logger& logger() const noexcept { return config_.logger; }
    /** @brief Shared handshake context. @return The context. */
    std::shared_ptr<const ServerAuthContext> auth_context() const noexcept { return auth_; }
    /** @brief Installation registry. @return The registry. */
    IClientRegistry& registry() noexcept { return *registry_; }
    /** @brief Authorizer. @return The BuiltinAuthorizer. */
    IAuthorizer& authorizer() noexcept { return *authorizer_; }
    /** @brief Counters, for updating. @return The counters. */
    EngineStats& mutable_stats() noexcept { return stats_; }
    /** @brief Application callbacks. @return The callbacks. */
    const EngineCallbacks& callbacks() const noexcept { return callbacks_; }
    /**
     * @brief Revocation generation.
     *
     * Incremented after every revocation-type change (installation, license,
     * seat). A connection authorised concurrently with one re-checks itself.
     *
     * @return The current generation.
     */
    uint64_t revocation_generation() const noexcept { return revocations_.load(); }
    /**
     * @brief Re-checks against the current stores whether an authorization still holds.
     *
     * False if the installation is unknown or not active; true if the decision names no license. For a named
     * license: false if the store lookup fails or the license is revoked; a license unknown to the store is
     * acceptable only if it was not verified; a verified license must still hold the installation's seat.
     * Expiry, product and features are not re-evaluated.
     *
     * @param[in] installation_id Authenticated installation.
     * @param[in] decision        Decision the session was authorised with.
     * @return True if the session may still open.
     */
    bool IsStillAuthorized(const proto::InstallationId& installation_id, const AuthorizationDecision& decision);
    /**
     * @brief Gives back the seat an authorization took.
     *
     * Used if the session is rejected afterwards because of a concurrent
     * revocation. Does nothing unless `decision.seat_newly_taken`; failures are ignored.
     *
     * @param[in] installation_id Installation that took the seat.
     * @param[in] decision        Decision that took it.
     */
    void ReleaseNewSeat(const proto::InstallationId& installation_id, const AuthorizationDecision& decision);
    /**
     * @brief Removes a connection that finished closing.
     *
     * Called outside any connection lock when a connection finished closing. A stream that is not closed yet
     * moves to the graceful-close list; an unauthenticated connection's place is kept until its stream is gone.
     *
     * @param[in] connection The closed connection.
     */
    void OnConnectionClosed(const std::shared_ptr<Connection>& connection);

private:
    friend class Connection;  // ReleaseUnauthenticated

    /** @brief A connection left the unauthenticated phase (see Connection::LeaveUnauthenticated). Lock-free. */
    void ReleaseUnauthenticated() noexcept { unauthenticated_.fetch_sub(1); }

    /**
     * @brief Stores configuration and callbacks; everything else is set up by Create().
     * @param[in] config    Configuration.
     * @param[in] callbacks Application callbacks.
     */
    ServerEngine(EngineConfig config, EngineCallbacks callbacks);
    /** @brief Stop() body; may throw on allocation failure. */
    void StopImpl();
    /**
     * @brief Admits or refuses an accepted stream (I/O worker thread).
     *
     * Refuses by closing the stream while stopping or if no TLS engine can be created, and (logged) at
     * max_connections (counting streams in graceful close) or at max_unauthenticated. Capacity check and
     * insertion are one atomic step under connections_mutex_. An admitted connection is counted as
     * unauthenticated and starts reading.
     *
     * @param[in] stream The accepted stream.
     */
    void OnAccept(std::shared_ptr<AsyncStream> stream);
    /**
     * @brief Sweeper thread body: every 250 ms ticks every connection (timeouts), reaps closed streams from
     *        the graceful-close list and force-closes those older than 5 s.
     */
    void SweeperLoop();
    /**
     * @brief Copies the current connections under connections_mutex_.
     * @return The connections.
     */
    std::vector<std::shared_ptr<Connection>> SnapshotConnections();
    /**
     * @brief Admin-side consistency for a product/license binding.
     *
     * A license the store knows must be active and for the same product; unknown licenses are only accepted
     * when licensing is not enforced.
     *
     * @param[in] product_id Product of the binding (empty: not checked).
     * @param[in] license_id License of the binding (empty: nothing to check).
     * @retval SG_OK               Consistent.
     * @retval SG_NOT_FOUND        Unknown license while require_license is set.
     * @retval SG_INVALID_STATE    The license is revoked.
     * @retval SG_INVALID_ARGUMENT The license is for another product.
     * @retval other               License store failure.
     */
    Status CheckLicenseBinding(const std::string& product_id, const std::string& license_id);
    /**
     * @brief Closes (CLOSE(AUTH_FAILED), SG_AUTH_FAILED) every connection for which @p match returns true.
     *
     * @p match is called without connections_mutex_ held.
     *
     * @param[in] match Predicate.
     * @return Number of connections closed.
     */
    size_t CloseMatching(const std::function<bool(Connection&)>& match);

    EngineConfig config_;        ///< Effective configuration.
    EngineCallbacks callbacks_;  ///< Application callbacks.
    std::shared_ptr<tls::ITlsContext> tls_context_;  ///< Server TLS context.
    std::unique_ptr<IClientRegistry> registry_;      ///< Installation registry.
    std::unique_ptr<ILicenseStore> licenses_;        ///< License store.
    std::unique_ptr<IAuthorizer> authorizer_;        ///< BuiltinAuthorizer.
    std::shared_ptr<const ServerAuthContext> auth_;  ///< Handshake context shared by connections.
    std::unique_ptr<IIoService> io_;                 ///< I/O service while running (lifecycle_mutex_).
    EngineStats stats_;                              ///< Counters.
    std::atomic<uint64_t> revocations_{0};           ///< Revocation generation.

    std::mutex lifecycle_mutex_;          ///< Serializes Start() and Stop().
    bool running_ = false;                ///< Started and not stopped (lifecycle_mutex_).
    std::atomic<bool> stopping_{false};   ///< Set by Stop() (until the next Start()): new connections are refused.
    uint16_t port_ = 0;                   ///< Bound port.

    std::mutex connections_mutex_;  ///< Guards connections_ and closing_.
    /** Connections by handle, from accept until their close was delivered. */
    std::map<SG_SessionHandle, std::shared_ptr<Connection>> connections_;
    /**
     * @brief A stream in its graceful-close phase.
     *
     * Streams in their graceful-close phase are held strongly (the Connection may
     * already be gone) until they closed or the timeout forces them shut; they
     * still count against max_connections, and a stream that never
     * authenticated also keeps its place in unauthenticated_ (otherwise a peer
     * that sends garbage and never closes would bypass max_unauthenticated).
     */
    struct ClosingStream {
        std::shared_ptr<AsyncStream> stream;  ///< The stream (held strongly).
        uint64_t since = 0;                   ///< Monotonic ms at which the graceful close began.
        bool unauthenticated = false;         ///< The stream holds a place in unauthenticated_.
    };
    std::vector<ClosingStream> closing_;  ///< Streams in their graceful-close phase (see ClosingStream).
    /**
     * Connections accepted but not yet authenticated, including their
     * graceful-close phase (see max_unauthenticated). Incremented only under
     * connections_mutex_; decremented under it too, except on authentication
     * (lock-free, so a concurrent check can only see too high a count).
     */
    std::atomic<uint32_t> unauthenticated_{0};
    std::atomic<SG_SessionHandle> next_handle_{1};  ///< Next session handle (assigned at accept, from 1).

    std::mutex sweeper_mutex_;              ///< Guards sweeper_stop_.
    std::condition_variable sweeper_cv_;    ///< Wakes the sweeper for shutdown.
    bool sweeper_stop_ = false;             ///< Tells the sweeper to exit.
    std::thread sweeper_;                   ///< Sweeper thread while running.
};

/**
 * @brief True while the current thread runs an application callback.
 *
 * Used to refuse Stop()/Destroy() (and SG_Server_Start()) from inside callbacks.
 *
 * @return True inside a CallbackScope.
 */
bool InApplicationCallback() noexcept;

/**
 * @brief Marks the current thread as running an application callback for the scope's lifetime.
 *
 * Nestable: the destructor restores the previous state.
 */
class CallbackScope {
public:
    /** @brief Enters the callback state on this thread. */
    CallbackScope() noexcept;
    /** @brief Restores the previous state. */
    ~CallbackScope();
    CallbackScope(const CallbackScope&) = delete;
    CallbackScope& operator=(const CallbackScope&) = delete;

private:
    bool previous_;  ///< State before this scope.
};

}  // namespace sg::server
