#include "core/server_engine.h"

#include "session/connection.h"
#include "storage/atomic_file.h"

#include "sockgate_common/core/clock.h"
#include "sockgate_common/protocol/enrollment_token.h"

#include <chrono>

namespace sg::server {
namespace {

constexpr uint32_t kSweepIntervalMs = 250;
constexpr uint64_t kGracefulCloseTimeoutMs = 5000;
constexpr uint32_t kDefaultTokenTtlMs = 24u * 3600 * 1000;
constexpr uint32_t kMaxTokenTtlMs = 30u * 24 * 3600 * 1000;

thread_local bool t_in_callback = false;

// Built-in policy (verified, active installation -> NORMAL session, no
// features) refined by the application's on_authorize hook, if any.
class EngineAuthorizer final : public IAuthorizer {
public:
    explicit EngineAuthorizer(const EngineCallbacks* callbacks) : callbacks_(callbacks) {}

    Status Authorize(const AuthorizationRequest& request, AuthorizationDecision* decision) override
    {
        decision->allow = request.record != nullptr && request.record->status == ClientStatus::kActive;
        decision->policy = proto::SessionPolicy::kNormal;
        decision->granted_features = 0;
        if (!decision->allow) {
            decision->deny_reason = "installation not active";
            return OkStatus();
        }
        if (callbacks_->authorize) {
            CallbackScope scope;
            const Status st = callbacks_->authorize(request.session_handle, request, decision);
            if (!st.ok()) {
                decision->allow = false;
                decision->deny_reason = "application callback failed";
            } else if (!decision->allow && decision->deny_reason.empty()) {
                decision->deny_reason = "denied by application";
            }
        }
        return OkStatus();
    }

private:
    const EngineCallbacks* callbacks_;
};

}  // namespace

bool InApplicationCallback() noexcept { return t_in_callback; }

CallbackScope::CallbackScope() noexcept : previous_(t_in_callback) { t_in_callback = true; }
CallbackScope::~CallbackScope() { t_in_callback = previous_; }

ServerEngine::ServerEngine(EngineConfig config, EngineCallbacks callbacks)
    : config_(std::move(config)), callbacks_(std::move(callbacks))
{
}

Status ServerEngine::Create(EngineConfig config, EngineCallbacks callbacks, std::unique_ptr<ServerEngine>* out)
{
    if (out == nullptr) return SG_INVALID_ARGUMENT;
    if (config.max_payload == 0 || config.max_payload > proto::kAbsoluteMaxPayload || config.max_connections == 0 ||
        config.handshake_timeout_ms == 0) {
        return SG_INVALID_ARGUMENT;
    }
    std::unique_ptr<ServerEngine> engine(new ServerEngine(std::move(config), std::move(callbacks)));
    EngineConfig& cfg = engine->config_;

    SG_TRY(tls::DefaultTlsProvider().CreateServerContext(cfg.tls, &engine->tls_context_));
    // The PEM key material is no longer needed once loaded into the TLS context.
    SecureZero(cfg.tls.private_key_pem.data(), cfg.tls.private_key_pem.size());
    cfg.tls.private_key_pem.clear();

    if (cfg.registry_path.empty()) {
        engine->registry_ = CreateMemoryClientRegistry();
    } else {
        SG_TRY(CreateFileClientRegistry(cfg.registry_path, &engine->registry_));
    }
    engine->authorizer_ = std::make_unique<EngineAuthorizer>(&engine->callbacks_);

    HandshakeConfig hs = cfg.handshake;
    if (hs.token_key.empty()) {
        // No configured secret: tokens are valid for this server instance only.
        hs.token_key.assign(32, 0);
        SG_TRY(crypto::RandomBytes(hs.token_key.data(), hs.token_key.size()));
    }
    if (engine->callbacks_.enroll) hs.enroll_validator = engine->callbacks_.enroll;
    std::shared_ptr<ServerAuthContext> auth;
    SG_TRY(ServerAuthContext::Create(std::move(hs), engine->registry_.get(), engine->authorizer_.get(), &auth));
    engine->auth_ = std::move(auth);
    *out = std::move(engine);
    return OkStatus();
}

ServerEngine::~ServerEngine() { Stop(); }

Status ServerEngine::Start()
{
    std::lock_guard<std::mutex> lifecycle(lifecycle_mutex_);
    if (running_) return SG_INVALID_STATE;
    stopping_ = false;
    io_ = CreateIoService();
    IoServiceOptions options;
    options.worker_threads = config_.worker_threads;
    Status st = io_->Start(options);
    if (st.ok()) {
        st = io_->Listen(config_.bind_address, config_.port,
                         [this](std::shared_ptr<AsyncStream> stream) { OnAccept(std::move(stream)); }, &port_);
    }
    if (!st.ok()) {
        io_->Stop();
        io_.reset();
        SG_LOGE(config_.logger, "event=listen_failed address=%s port=%u err=%s", config_.bind_address.c_str(),
                static_cast<unsigned>(config_.port), st.name());
        return st;
    }
    {
        std::lock_guard<std::mutex> lock(sweeper_mutex_);
        sweeper_stop_ = false;
    }
    sweeper_ = std::thread([this]() { SweeperLoop(); });
    running_ = true;
    SG_LOGI(config_.logger, "event=server_started address=%s port=%u", config_.bind_address.c_str(),
            static_cast<unsigned>(port_));
    return OkStatus();
}

void ServerEngine::Stop() noexcept
{
    try {
        StopImpl();
    } catch (...) {
        // Allocation failure during shutdown: the I/O service is still
        // stopped by its own destructor.
    }
}

void ServerEngine::StopImpl()
{
    std::lock_guard<std::mutex> lifecycle(lifecycle_mutex_);
    if (!running_) return;
    stopping_ = true;

    // Tell authenticated peers why the connection goes away, then give the
    // I/O service a moment to flush before tearing everything down.
    for (const auto& conn : SnapshotConnections()) conn->Close(proto::CloseReason::kServerShutdown, SG_CLOSED);
    for (int i = 0; i < 50 && io_->StreamCount() > 0; ++i) std::this_thread::sleep_for(std::chrono::milliseconds(10));

    {
        std::lock_guard<std::mutex> lock(sweeper_mutex_);
        sweeper_stop_ = true;
    }
    sweeper_cv_.notify_all();
    if (sweeper_.joinable()) sweeper_.join();

    io_->Stop();  // closes remaining streams, joins the workers
    {
        std::lock_guard<std::mutex> lock(connections_mutex_);
        connections_.clear();
        closing_.clear();
    }
    io_.reset();
    running_ = false;
    SG_LOGI(config_.logger, "event=server_stopped");
}

void ServerEngine::OnAccept(std::shared_ptr<AsyncStream> stream)
{
    std::unique_ptr<tls::ITlsEngine> tls;
    if (stopping_.load() || !tls_context_->CreateEngine(&tls).ok()) {
        stream->Close();
        return;
    }
    const SG_SessionHandle handle = next_handle_.fetch_add(1);
    auto conn = std::make_shared<Connection>(this, stream, std::move(tls), handle, MonotonicMs());
    {
        // Capacity check and insertion are one atomic step; sockets in their
        // graceful-close phase still occupy descriptors and count too.
        std::lock_guard<std::mutex> lock(connections_mutex_);
        if (stopping_.load() || connections_.size() + closing_.size() >= config_.max_connections) {
            SG_LOGW(config_.logger, "event=connection_refused peer=%s reason=%s", stream->PeerAddress().c_str(),
                    stopping_.load() ? "stopping" : "max_connections");
            stream->Close();
            return;
        }
        connections_[handle] = conn;
    }
    stats_.total_connections.fetch_add(1);
    conn->Start();
}

void ServerEngine::OnConnectionClosed(const std::shared_ptr<Connection>& connection)
{
    std::lock_guard<std::mutex> lock(connections_mutex_);
    connections_.erase(connection->handle());
    if (!connection->stream()->IsClosed()) closing_.emplace_back(connection->stream(), MonotonicMs());
}

std::vector<std::shared_ptr<Connection>> ServerEngine::SnapshotConnections()
{
    std::lock_guard<std::mutex> lock(connections_mutex_);
    std::vector<std::shared_ptr<Connection>> out;
    out.reserve(connections_.size());
    for (const auto& entry : connections_) out.push_back(entry.second);
    return out;
}

void ServerEngine::SweeperLoop()
{
    for (;;) {
        {
            std::unique_lock<std::mutex> lock(sweeper_mutex_);
            if (sweeper_cv_.wait_for(lock, std::chrono::milliseconds(kSweepIntervalMs), [this]() { return sweeper_stop_; })) {
                return;
            }
        }
        try {
            for (const auto& conn : SnapshotConnections()) conn->Tick();

            std::vector<std::shared_ptr<AsyncStream>> force;
            {
                std::lock_guard<std::mutex> lock(connections_mutex_);
                const uint64_t now = MonotonicMs();  // taken under the lock that guards closing_
                auto it = closing_.begin();
                while (it != closing_.end()) {
                    if (it->first->IsClosed()) {
                        it = closing_.erase(it);
                    } else if (ElapsedMs(now, it->second) > kGracefulCloseTimeoutMs) {
                        force.push_back(std::move(it->first));
                        it = closing_.erase(it);
                    } else {
                        ++it;
                    }
                }
            }
            for (const auto& s : force) s->Close();
        } catch (...) {
            // Out of memory while sweeping: try again on the next tick.
        }
    }
}

Status ServerEngine::Send(SG_SessionHandle session, ByteView data, uint64_t reply_to_request_id)
{
    std::shared_ptr<Connection> conn;
    {
        std::lock_guard<std::mutex> lock(connections_mutex_);
        auto it = connections_.find(session);
        if (it == connections_.end()) return SG_NOT_FOUND;
        conn = it->second;
    }
    return conn->Send(data, reply_to_request_id);
}

Status ServerEngine::CloseSession(SG_SessionHandle session)
{
    std::shared_ptr<Connection> conn;
    {
        std::lock_guard<std::mutex> lock(connections_mutex_);
        auto it = connections_.find(session);
        if (it == connections_.end()) return SG_NOT_FOUND;
        conn = it->second;
    }
    conn->Close(proto::CloseReason::kNormal, SG_CLOSED);
    return OkStatus();
}

Status ServerEngine::GetSession(SG_SessionHandle session, SessionSnapshot* out)
{
    std::shared_ptr<Connection> conn;
    {
        std::lock_guard<std::mutex> lock(connections_mutex_);
        auto it = connections_.find(session);
        if (it == connections_.end()) return SG_NOT_FOUND;
        conn = it->second;
    }
    return conn->Snapshot(out) ? OkStatus() : Status(SG_NOT_FOUND);
}

Status ServerEngine::RegisterClient(const ClientRecord& record)
{
    ClientRecord copy = record;
    if (copy.created_at_ms == 0) copy.created_at_ms = UnixTimeMs();
    return registry_->Register(copy);
}

Status ServerEngine::RevokeClient(const proto::InstallationId& installation_id)
{
    SG_TRY(registry_->Revoke(installation_id));
    // Revocation takes effect immediately for live sessions.
    size_t closed = 0;
    for (const auto& conn : SnapshotConnections()) {
        if (conn->IsInstallation(installation_id)) {
            conn->Close(proto::CloseReason::kAuthFailed, SG_AUTH_FAILED);
            ++closed;
        }
    }
    SG_LOGI(config_.logger, "event=installation_revoked installation=%s sessions_closed=%zu",
            ShortId(installation_id).c_str(), closed);
    return OkStatus();
}

Status ServerEngine::IssueEnrollmentToken(const std::string& product_id, const std::string& license_id,
                                          uint32_t ttl_ms, std::string* token)
{
    if (token == nullptr || product_id.empty()) return SG_INVALID_ARGUMENT;
    if (ttl_ms == 0) ttl_ms = kDefaultTokenTtlMs;
    if (ttl_ms > kMaxTokenTtlMs) return SG_INVALID_ARGUMENT;
    proto::EnrollmentClaims claims;
    SG_TRY(crypto::RandomArray(&claims.token_id));
    claims.product_id = product_id;
    claims.license_id = license_id;
    claims.issued_at_ms = auth_->UnixNow();
    claims.expires_at_ms = claims.issued_at_ms + ttl_ms;
    SG_TRY(proto::BuildEnrollmentToken(auth_->config.token_key, claims, token));
    SG_LOGI(config_.logger, "event=enrollment_token_issued token=%s product=%s ttl_ms=%u",
            ShortId(claims.token_id).c_str(), product_id.c_str(), ttl_ms);
    return OkStatus();
}

uint64_t ServerEngine::ActiveConnections()
{
    std::lock_guard<std::mutex> lock(connections_mutex_);
    return connections_.size();
}

uint64_t ServerEngine::ActiveSessions() { return stats_.active_sessions.load(); }

}  // namespace sg::server
