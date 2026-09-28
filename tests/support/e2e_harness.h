// End-to-end harness shared by the tests that drive both public C APIs over
// real sockets: a callback-recording TestServer, client factory and helpers.
#pragma once

#include "sg_test.h"

#include "support/test_pki.h"

#include <sockgate/client.h>
#include <sockgate/server.h>

#include <chrono>
#include <condition_variable>
#include <cstdio>
#include <cstdlib>
#include <functional>
#include <memory>
#include <mutex>
#include <string>
#include <utility>
#include <vector>

namespace sgtest {

// Set SG_TEST_LOG=1 to print server logs while debugging a test.
inline bool TestLoggingEnabled()
{
#ifdef _MSC_VER
    char* value = nullptr;
    size_t len = 0;
    const bool set = _dupenv_s(&value, &len, "SG_TEST_LOG") == 0 && value != nullptr;
    std::free(value);
    return set;
#else
    return std::getenv("SG_TEST_LOG") != nullptr;
#endif
}

inline const TestCert& Ca()
{
    static const TestCert ca = CreateRootCa("SockGate E2E CA");
    return ca;
}
inline const TestCert& Leaf()
{
    static const TestCert leaf = IssueLocalhostServer(Ca());
    return leaf;
}

class TestServer {
public:
    std::function<void(SG_ServerOptions&)> configure;
    std::function<SG_Status(const SG_AuthRequest*, SG_AuthDecision*)> authorize;
    bool echo = true;

    SG_Server* server = nullptr;
    uint16_t port = 0;

    std::mutex mutex;
    std::condition_variable cv;
    std::vector<SG_SessionHandle> opened;
    std::vector<std::pair<SG_SessionHandle, SG_Status>> closed;
    std::vector<std::string> messages;

    ~TestServer() { Destroy(); }

    void Start()
    {
        SG_ServerCallbacks cb;
        SG_ServerCallbacks_Init(&cb);
        cb.user = this;
        cb.on_session_opened = &OnOpened;
        cb.on_message = &OnMessage;
        cb.on_session_closed = &OnClosed;
        if (authorize) cb.on_authorize = &OnAuthorize;

        SG_ServerOptions opts;
        SG_ServerOptions_Init(&opts);
        opts.bind_address = "127.0.0.1";
        opts.port = 0;
        opts.tls_cert_chain_pem = Leaf().cert_pem.c_str();
        opts.tls_private_key_pem = Leaf().key_pem.c_str();
        opts.worker_threads = 4;
        opts.callbacks = &cb;
        if (TestLoggingEnabled()) {
            opts.log_callback = &LogToStderr;
            opts.log_level = SG_LOG_DEBUG;
        }
        if (configure) configure(opts);
        SG_ASSERT_OK(SG_Server_Create(&opts, &server));
        SG_ASSERT_OK(SG_Server_Start(server));
        SG_ASSERT_OK(SG_Server_GetPort(server, &port));
    }

    void Destroy()
    {
        if (server != nullptr) {
            SG_Server_Destroy(server);
            server = nullptr;
        }
    }

    void Register(SG_Client* client) { SG_ASSERT_OK(TryRegister(client)); }

    // Registers the client's installation, optionally bound to a product / license.
    SG_Status TryRegister(SG_Client* client, const char* product_id = nullptr, const char* license_id = nullptr)
    {
        SG_IdentityInfo id;
        SG_IdentityInfo_Init(&id);
        SG_ASSERT_OK(SG_Client_EnsureIdentity(client, &id));
        SG_ClientRecord rec;
        SG_ClientRecord_Init(&rec);
        rec.public_key = id.public_key;
        rec.product_id = product_id;
        rec.license_id = license_id;
        return SG_Server_RegisterClient(server, &rec);
    }

    bool WaitClosed(size_t count, int timeout_ms = 5000)
    {
        std::unique_lock<std::mutex> lock(mutex);
        return cv.wait_for(lock, std::chrono::milliseconds(timeout_ms), [&]() { return closed.size() >= count; });
    }

    bool WaitOpened(size_t count, int timeout_ms = 5000)
    {
        std::unique_lock<std::mutex> lock(mutex);
        return cv.wait_for(lock, std::chrono::milliseconds(timeout_ms), [&]() { return opened.size() >= count; });
    }

private:
    static void SG_CALL LogToStderr(void*, uint32_t level, const char* message)
    {
        std::fprintf(stderr, "[server:%u] %s\n", level, message);
    }

    static void SG_CALL OnOpened(void* user, const SG_ServerSessionInfo* info)
    {
        auto* self = static_cast<TestServer*>(user);
        std::lock_guard<std::mutex> lock(self->mutex);
        self->opened.push_back(info->session);
        self->cv.notify_all();
    }

    static void SG_CALL OnMessage(void* user, SG_SessionHandle session, const void* data, size_t size,
                                  const SG_MessageInfo* info)
    {
        auto* self = static_cast<TestServer*>(user);
        {
            std::lock_guard<std::mutex> lock(self->mutex);
            self->messages.emplace_back(static_cast<const char*>(data), size);
            self->cv.notify_all();
        }
        if (self->echo) SG_Server_SendEx(self->server, session, data, size, info->request_id);
    }

    static void SG_CALL OnClosed(void* user, SG_SessionHandle session, SG_Status reason)
    {
        auto* self = static_cast<TestServer*>(user);
        std::lock_guard<std::mutex> lock(self->mutex);
        self->closed.emplace_back(session, reason);
        self->cv.notify_all();
    }

    static SG_Status SG_CALL OnAuthorize(void* user, const SG_AuthRequest* request, SG_AuthDecision* decision)
    {
        return static_cast<TestServer*>(user)->authorize(request, decision);
    }
};

struct ClientOptions {
    uint32_t flags = 0;
    uint32_t io_timeout_ms = 10000;
    uint32_t max_payload = 0;
    const char* product_id = "e2e-product";
    const char* license_id = nullptr;
    uint64_t requested_features = 0;
};

inline SG_Client* NewClient(const ClientOptions& o = ClientOptions(), const char* identity = "e2e-app")
{
    SG_ClientConfig cfg;
    SG_ClientConfig_Init(&cfg);
    cfg.identity_name = identity;
    cfg.key_store_type = SG_KEYSTORE_MEMORY;
    cfg.flags = o.flags;
    cfg.product_id = o.product_id;
    cfg.license_id = o.license_id;
    cfg.requested_features = o.requested_features;
    cfg.io_timeout_ms = o.io_timeout_ms;
    cfg.connect_timeout_ms = 5000;
    if (o.max_payload != 0) cfg.max_payload_size = o.max_payload;
    SG_Client* client = nullptr;
    SG_ASSERT_OK(SG_Client_Create(&cfg, &client));
    return client;
}

struct ClientDeleter {
    void operator()(SG_Client* c) const { SG_Client_Destroy(c); }
};
using ClientPtr = std::unique_ptr<SG_Client, ClientDeleter>;

inline SG_ServerConfig Target(uint16_t port)
{
    SG_ServerConfig t;
    SG_ServerConfig_Init(&t);
    t.host = "127.0.0.1";
    t.port = port;
    t.ca_pem = Ca().cert_pem.c_str();
    return t;
}

inline void ConnectAndAuth(SG_Client* c, uint16_t port)
{
    const SG_ServerConfig t = Target(port);
    SG_ASSERT_OK(SG_Client_Connect(c, &t));
    SG_ASSERT_OK(SG_Client_Authenticate(c));
}

inline std::string ReceiveText(SG_Client* c, uint32_t timeout_ms = 5000, SG_MessageInfo* info = nullptr)
{
    char buf[4096];
    size_t n = 0;
    const SG_Status st = SG_Client_ReceiveEx(c, buf, sizeof(buf), &n, info, timeout_ms);
    if (st != SG_OK) return std::string("<") + SG_StatusString(st) + ">";
    return std::string(buf, n);
}

inline uint32_t StateOf(SG_Client* c)
{
    uint32_t s = 0;
    SG_Client_GetState(c, &s);
    return s;
}

}  // namespace sgtest
