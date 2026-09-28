// Blocking TCP transport with timeouts for the client.
//
// Sockets are non-blocking internally; blocking behaviour and timeouts are
// implemented by waiting in bounded slices, re-checking a shutdown flag on
// every slice. Shutdown() may be called from any thread and wakes blocked
// operations immediately (socket shutdown) or at the latest after one slice.
#pragma once

#include "sockgate_common/net/transport.h"
#include "sockgate_common/platform/socket.h"

#include <condition_variable>
#include <cstdint>
#include <mutex>
#include <string>

namespace sg::client {

struct TcpTransportOptions {
    uint32_t connect_timeout_ms = 10000;
    uint32_t io_timeout_ms = 30000;  // net::kNoTimeout = wait indefinitely
};

class TcpTransport final : public net::ITransport {
public:
    explicit TcpTransport(const TcpTransportOptions& options);
    ~TcpTransport() override;

    TcpTransport(const TcpTransport&) = delete;
    TcpTransport& operator=(const TcpTransport&) = delete;

    Status Connect(const net::Endpoint& endpoint) override;
    Status Send(const uint8_t* data, size_t size) override;
    Status Receive(uint8_t* buffer, size_t capacity, size_t* received) override;
    Status ReceiveFor(uint8_t* buffer, size_t capacity, size_t* received, uint32_t timeout_ms) override;
    void Shutdown() noexcept override;
    void Close() noexcept override;
    std::string PeerAddress() const override;

private:
    class InFlight;

    Status ConnectOne(const platform::SocketAddress& address, uint32_t timeout_ms);

    const TcpTransportOptions options_;
    platform::NetworkRuntime runtime_;

    mutable std::mutex mutex_;
    std::condition_variable idle_cv_;
    platform::NativeSocket socket_ = platform::kInvalidSocket;
    bool shutdown_ = false;
    bool connected_ = false;
    int in_flight_ = 0;
    std::string peer_;

    std::mutex send_mutex_;     // serialises concurrent senders
    std::mutex receive_mutex_;  // serialises concurrent receivers
};

}  // namespace sg::client
