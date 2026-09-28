// Test network intermediaries: forwarding proxies (HTTP CONNECT, SOCKS4a,
// SOCKS5) and a TLS-terminating MITM relay that models a user-installed CA.
#pragma once

#include "support/test_pki.h"

#include "sockgate_common/net/transport.h"
#include "sockgate_common/platform/socket.h"

#include <atomic>
#include <memory>
#include <mutex>
#include <string>
#include <thread>
#include <vector>

namespace sgtest {

// ITransport over an accepted (blocking) socket, for test servers.
class SocketTransport final : public sg::net::ITransport {
public:
    explicit SocketTransport(sg::platform::NativeSocket socket) : socket_(socket) {}
    ~SocketTransport() override { Close(); }
    sg::Status Connect(const sg::net::Endpoint&) override { return SG_NOT_SUPPORTED; }
    sg::Status Send(const uint8_t* data, size_t size) override;
    sg::Status SendFor(const uint8_t* data, size_t size, uint32_t timeout_ms) override;
    sg::Status Receive(uint8_t* buffer, size_t capacity, size_t* received) override;
    sg::Status ReceiveFor(uint8_t* buffer, size_t capacity, size_t* received, uint32_t timeout_ms) override;
    void Shutdown() noexcept override;
    void Close() noexcept override;
    std::string PeerAddress() const override { return "test-peer"; }

private:
    std::mutex mutex_;
    sg::platform::NativeSocket socket_;
    bool closed_ = false;
};

class TestProxy {
public:
    enum class Kind { kHttpConnect, kSocks4a, kSocks5 };
    enum class Misbehaviour { kNone, kRefuse, kGarbage, kHugeHeader, kSilent };

    struct Options {
        Kind kind = Kind::kHttpConnect;
        std::string required_user;
        std::string required_password;
        Misbehaviour misbehaviour = Misbehaviour::kNone;
        uint32_t reply_delay_ms = 0;  // delay before the "connected" reply
    };

    explicit TestProxy(Options options);
    ~TestProxy();

    uint16_t port() const { return port_; }
    int tunnels() const { return tunnels_.load(); }
    std::string last_target();
    // Every byte relayed in either direction (to check that it is ciphertext).
    std::string captured();

private:
    void AcceptLoop();
    void Serve(sg::platform::NativeSocket client);
    bool Negotiate(SocketTransport& client, std::string* host, uint16_t* port);

    Options options_;
    sg::platform::NetworkRuntime runtime_;
    sg::platform::NativeSocket listener_ = sg::platform::kInvalidSocket;
    uint16_t port_ = 0;
    std::atomic<bool> stopping_{false};
    std::atomic<int> tunnels_{0};
    std::thread acceptor_;
    std::mutex mutex_;
    std::vector<std::thread> workers_;
    std::vector<std::shared_ptr<sg::net::ITransport>> live_;
    std::string last_target_;
    std::string captured_;
};

// Terminates TLS towards the client with `impostor` (a certificate from a CA
// the victim wrongly trusts) and opens its own TLS session to the real
// server, relaying the decrypted SockGate stream unchanged in both directions.
class TlsMitmRelay {
public:
    TlsMitmRelay(const TestCert& impostor, const TestCert& real_ca, uint16_t real_port);
    ~TlsMitmRelay();
    uint16_t port() const { return port_; }
    int sessions() const { return sessions_.load(); }

private:
    void AcceptLoop();
    void Serve(sg::platform::NativeSocket client);

    TestCert impostor_;
    TestCert real_ca_;
    uint16_t real_port_;
    sg::platform::NetworkRuntime runtime_;
    sg::platform::NativeSocket listener_ = sg::platform::kInvalidSocket;
    uint16_t port_ = 0;
    std::atomic<bool> stopping_{false};
    std::atomic<int> sessions_{0};
    std::thread acceptor_;
    std::mutex mutex_;
    std::vector<std::thread> workers_;
    std::vector<std::shared_ptr<sg::net::ITransport>> live_;
};

}  // namespace sgtest
