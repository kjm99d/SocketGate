#pragma once
/**
 * @file
 * @brief Blocking TCP transport with timeouts for the client.
 *
 * Sockets are non-blocking internally; blocking behaviour and timeouts are implemented by waiting in bounded slices
 * (200 ms), re-checking a shutdown flag on every slice. Shutdown() may be called from any thread and wakes blocked
 * operations immediately (socket shutdown) or at the latest after one slice.
 */

#include "sockgate_common/net/transport.h"
#include "sockgate_common/platform/socket.h"

#include <condition_variable>
#include <cstdint>
#include <mutex>
#include <string>

namespace sg::client {

/** @brief Timeouts of a TcpTransport. */
struct TcpTransportOptions {
    uint32_t connect_timeout_ms = 10000;  ///< Budget for name resolution and all connect attempts (ms); 0 = no limit.
    uint32_t io_timeout_ms = 30000;  ///< Send() / Receive() timeout (ms); net::kNoTimeout = wait indefinitely.
};

/**
 * @brief net::ITransport over one TCP connection.
 *
 * @note Thread safety: a sender and a receiver may run concurrently; concurrent senders (and concurrent receivers)
 *       are serialised. Shutdown() and Close() may be called from any thread. An operation registers as in flight
 *       before it waits for its serial lock, so Close() never releases the socket underneath it. Locks: send_mutex_
 *       or receive_mutex_ before mutex_; mutex_ is held only briefly.
 */
class TcpTransport final : public net::ITransport {
public:
    /**
     * @brief Creates an unconnected transport.
     * @param[in] options Timeouts (copied).
     */
    explicit TcpTransport(const TcpTransportOptions& options);
    /** @brief Close()s the transport. */
    ~TcpTransport() override;

    TcpTransport(const TcpTransport&) = delete;
    TcpTransport& operator=(const TcpTransport&) = delete;

    /**
     * @brief Resolves @p endpoint and connects to the resolved addresses in turn.
     *
     * One connect_timeout_ms deadline starts before name resolution; each attempt gets only what is left. A
     * resolver call itself cannot be interrupted, but no connect starts after the budget. Enables TCP_NODELAY and
     * keep-alive on the connected socket. Network runtime and name resolution errors are passed through.
     *
     * @param[in] endpoint Host (DNS name or IP literal) and port.
     * @retval SG_OK               Connected.
     * @retval SG_INVALID_ARGUMENT Empty host or port 0.
     * @retval SG_INVALID_STATE    Already connected or connecting.
     * @retval SG_CLOSED           Shutdown() was requested.
     * @retval SG_TIMEOUT          The budget ran out.
     * @retval SG_NETWORK_ERROR    No address could be connected (or the error of the last attempt).
     */
    Status Connect(const net::Endpoint& endpoint) override;
    /**
     * @brief SendFor() with the configured io_timeout_ms.
     * @param[in] data Bytes to send; may be nullptr only when @p size is 0.
     * @param[in] size Number of bytes.
     * @return As SendFor().
     */
    Status Send(const uint8_t* data, size_t size) override;
    /**
     * @brief Sends every byte or fails.
     * @param[in] data       Bytes to send; may be nullptr only when @p size is 0.
     * @param[in] size       Number of bytes.
     * @param[in] timeout_ms One deadline for the whole buffer (ms); net::kNoTimeout waits indefinitely.
     * @retval SG_OK               All bytes sent.
     * @retval SG_INVALID_ARGUMENT @p data is nullptr with a non-zero @p size.
     * @retval SG_CLOSED           Shut down, or not connected.
     * @retval SG_TIMEOUT          The deadline passed.
     * @retval SG_NETWORK_ERROR    Socket error.
     */
    Status SendFor(const uint8_t* data, size_t size, uint32_t timeout_ms) override;
    /**
     * @brief ReceiveFor() with the configured io_timeout_ms.
     * @param[out] buffer   Destination; must not be nullptr.
     * @param[in]  capacity Size of @p buffer; must not be 0.
     * @param[out] received Receives the number of bytes stored.
     * @return As ReceiveFor().
     */
    Status Receive(uint8_t* buffer, size_t capacity, size_t* received) override;
    /**
     * @brief Receives between 1 and @p capacity bytes.
     * @param[out] buffer     Destination; must not be nullptr.
     * @param[in]  capacity   Size of @p buffer; must not be 0.
     * @param[out] received   Receives the number of bytes stored (0 on failure).
     * @param[in]  timeout_ms Deadline (ms); net::kNoTimeout waits indefinitely.
     * @retval SG_OK               At least one byte received.
     * @retval SG_INVALID_ARGUMENT A nullptr argument or @p capacity 0.
     * @retval SG_CLOSED           Orderly end-of-stream, shut down, or not connected.
     * @retval SG_TIMEOUT          The deadline passed.
     * @retval SG_NETWORK_ERROR    Socket error.
     */
    Status ReceiveFor(uint8_t* buffer, size_t capacity, size_t* received, uint32_t timeout_ms) override;
    /**
     * @brief Idempotent: marks the transport shut down and shuts the socket down in both directions.
     *
     * Wakes waiting operations (immediately, or within one slice); every later operation fails with SG_CLOSED.
     * Does not release the socket.
     */
    void Shutdown() noexcept override;
    /**
     * @brief Shutdown(), then waits until no operation is in flight and releases the socket.
     * @note Blocks until running operations have left (they notice the shutdown within one slice).
     */
    void Close() noexcept override;
    /**
     * @brief Address of the connected peer.
     * @return "1.2.3.4:443" or "[::1]:443"; empty before a successful Connect().
     */
    std::string PeerAddress() const override;

private:
    /**
     * @brief Registers an operation as in flight so Close() does not release the socket underneath it.
     *
     * Fails with SG_CLOSED once Shutdown() has been requested (or without a socket).
     */
    class InFlight;

    /**
     * @brief One non-blocking connect attempt.
     *
     * The socket is published in socket_ first so Shutdown() can interrupt the connect.
     *
     * @param[in] address    Resolved address.
     * @param[in] timeout_ms Budget for this attempt (ms); 0 = no limit.
     * @retval SG_OK      Connected.
     * @retval SG_CLOSED  Shutdown() was requested, or Close() released the socket meanwhile.
     * @retval SG_TIMEOUT The budget ran out.
     * @return Otherwise the socket error.
     */
    Status ConnectOne(const platform::SocketAddress& address, uint32_t timeout_ms);

    const TcpTransportOptions options_;  ///< Timeouts.
    platform::NetworkRuntime runtime_;   ///< Keeps the network stack initialised (WSAStartup on Windows).

    mutable std::mutex mutex_;             ///< Guards the members below up to peer_.
    std::condition_variable idle_cv_;      ///< Signalled when in_flight_ drops to 0 (Close() waits on it).
    platform::NativeSocket socket_ = platform::kInvalidSocket;  ///< Current socket, or kInvalidSocket.
    bool shutdown_ = false;                ///< Set by Shutdown(); never cleared.
    bool connected_ = false;               ///< True after a successful Connect(); cleared by Close().
    int in_flight_ = 0;                    ///< Operations currently using socket_.
    std::string peer_;                     ///< Connected peer address.

    std::mutex send_mutex_;     ///< Serialises concurrent senders.
    std::mutex receive_mutex_;  ///< Serialises concurrent receivers.
};

}  // namespace sg::client
