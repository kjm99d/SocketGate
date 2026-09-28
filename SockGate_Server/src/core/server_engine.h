// ServerEngine: accept loop, connection/session management, sweeper and the
// bridge to application callbacks.
//
// Lock order: engine mutexes are never acquired while a Connection's mutex
// is held; connections report back through events delivered outside it.
#pragma once

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

struct SessionSnapshot {
    SG_SessionHandle handle = SG_INVALID_SESSION_HANDLE;
    proto::SessionId session_id{};
    proto::InstallationId installation_id{};
    proto::SessionPolicy policy = proto::SessionPolicy::kNone;
    uint32_t epoch = 0;
    uint64_t granted_features = 0;
    uint64_t license_expires_at_ms = 0;
    LicenseCheck license_status = LicenseCheck::kNone;
    uint64_t expires_in_ms = 0;
    bool enrolled = false;
    std::string peer_address;
    std::string product_id;
    std::string license_id;
};

struct EngineCallbacks {
    // App authorisation hook; `decision` is pre-filled with the built-in result.
    std::function<Status(SG_SessionHandle, const AuthorizationRequest&, AuthorizationDecision*)> authorize;
    EnrollValidator enroll;
    std::function<void(const SessionSnapshot&)> session_opened;
    std::function<void(SG_SessionHandle, const uint8_t*, size_t, uint64_t request_id, uint32_t flags)> message;
    std::function<void(SG_SessionHandle, SG_Status)> session_closed;
};

struct EngineConfig {
    std::string bind_address = "0.0.0.0";
    uint16_t port = 0;
    tls::TlsServerConfig tls;
    HandshakeConfig handshake;
    std::string registry_path;
    std::string license_path;
    bool require_license = false;
    bool allow_license_activation = false;
    IntegrityPolicy integrity;
    uint32_t worker_threads = 0;
    uint32_t max_connections = 10'000;
    uint32_t handshake_timeout_ms = 15'000;
    uint32_t idle_timeout_ms = 300'000;
    uint32_t max_payload = 1u << 20;
    uint32_t min_reauth_interval_ms = 10'000;
    bool require_app_encryption = false;
    Logger logger;
};

struct EngineStats {
    std::atomic<uint64_t> active_sessions{0};
    std::atomic<uint64_t> total_connections{0};
    std::atomic<uint64_t> auth_succeeded{0};
    std::atomic<uint64_t> auth_failed{0};
    std::atomic<uint64_t> protocol_errors{0};
    std::atomic<uint64_t> messages_received{0};
    std::atomic<uint64_t> messages_sent{0};
};

class ServerEngine {
public:
    static Status Create(EngineConfig config, EngineCallbacks callbacks, std::unique_ptr<ServerEngine>* out);
    ~ServerEngine();

    ServerEngine(const ServerEngine&) = delete;
    ServerEngine& operator=(const ServerEngine&) = delete;

    Status Start();
    void Stop() noexcept;
    uint16_t port() const noexcept { return port_; }

    Status Send(SG_SessionHandle session, ByteView data, uint64_t reply_to_request_id);
    Status CloseSession(SG_SessionHandle session);
    Status GetSession(SG_SessionHandle session, SessionSnapshot* out);

    Status RegisterClient(const ClientRecord& record);
    Status RevokeClient(const proto::InstallationId& installation_id);
    Status IssueEnrollmentToken(const std::string& product_id, const std::string& license_id, uint32_t ttl_ms,
                                std::string* token);

    Status AddLicense(const LicenseRecord& record);
    Status RevokeLicense(const std::string& license_id);
    Status ReleaseLicenseSeat(const std::string& license_id, const proto::InstallationId& installation_id);
    Status GetLicense(const std::string& license_id, LicenseRecord* out);

    uint64_t ActiveConnections();
    uint64_t ActiveSessions();
    const EngineStats& stats() const noexcept { return stats_; }

    // ---- used by Connection ----------------------------------------------------
    const EngineConfig& config() const noexcept { return config_; }
    const Logger& logger() const noexcept { return config_.logger; }
    std::shared_ptr<const ServerAuthContext> auth_context() const noexcept { return auth_; }
    IClientRegistry& registry() noexcept { return *registry_; }
    IAuthorizer& authorizer() noexcept { return *authorizer_; }
    EngineStats& mutable_stats() noexcept { return stats_; }
    const EngineCallbacks& callbacks() const noexcept { return callbacks_; }
    // Incremented after every revocation-type change (installation, license,
    // seat). A connection authorised concurrently with one re-checks itself.
    uint64_t revocation_generation() const noexcept { return revocations_.load(); }
    bool IsStillAuthorized(const proto::InstallationId& installation_id, const AuthorizationDecision& decision);
    // Gives back the seat an authorization took if the session is rejected
    // afterwards because of a concurrent revocation.
    void ReleaseNewSeat(const proto::InstallationId& installation_id, const AuthorizationDecision& decision);
    // Called outside any connection lock when a connection finished closing.
    void OnConnectionClosed(const std::shared_ptr<Connection>& connection);

private:
    ServerEngine(EngineConfig config, EngineCallbacks callbacks);
    void StopImpl();
    void OnAccept(std::shared_ptr<AsyncStream> stream);
    void SweeperLoop();
    std::vector<std::shared_ptr<Connection>> SnapshotConnections();
    Status CheckLicenseBinding(const std::string& product_id, const std::string& license_id);
    size_t CloseMatching(const std::function<bool(Connection&)>& match);

    EngineConfig config_;
    EngineCallbacks callbacks_;
    std::shared_ptr<tls::ITlsContext> tls_context_;
    std::unique_ptr<IClientRegistry> registry_;
    std::unique_ptr<ILicenseStore> licenses_;
    std::unique_ptr<IAuthorizer> authorizer_;
    std::shared_ptr<const ServerAuthContext> auth_;
    std::unique_ptr<IIoService> io_;
    EngineStats stats_;
    std::atomic<uint64_t> revocations_{0};

    std::mutex lifecycle_mutex_;
    bool running_ = false;
    std::atomic<bool> stopping_{false};
    uint16_t port_ = 0;

    std::mutex connections_mutex_;
    std::map<SG_SessionHandle, std::shared_ptr<Connection>> connections_;
    // Streams in their graceful-close phase. Held strongly (the Connection may
    // already be gone) until they closed or the timeout forces them shut; they
    // still count against max_connections.
    std::vector<std::pair<std::shared_ptr<AsyncStream>, uint64_t>> closing_;
    std::atomic<SG_SessionHandle> next_handle_{1};

    std::mutex sweeper_mutex_;
    std::condition_variable sweeper_cv_;
    bool sweeper_stop_ = false;
    std::thread sweeper_;
};

// True while the current thread runs an application callback (used to refuse
// Stop()/Destroy() from inside callbacks).
bool InApplicationCallback() noexcept;

class CallbackScope {
public:
    CallbackScope() noexcept;
    ~CallbackScope();
    CallbackScope(const CallbackScope&) = delete;
    CallbackScope& operator=(const CallbackScope&) = delete;

private:
    bool previous_;
};

}  // namespace sg::server
