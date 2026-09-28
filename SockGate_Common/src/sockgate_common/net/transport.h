#pragma once
/**
 * @file
 * @brief Byte-stream transport abstraction.
 *
 * Used by the client (tests also wrap accepted sockets in one: sgtest::SocketTransport). TLS runs on
 * top of an ITransport via memory BIOs, so this interface carries ciphertext only.
 */

#include "sockgate_common/core/status.h"

#include <cstddef>
#include <cstdint>
#include <string>

namespace sg::net {

/** @brief Remote address to connect to. */
struct Endpoint {
    std::string host;  ///< DNS name, IPv4 literal or IPv6 literal (without brackets)
    uint16_t port = 0;  ///< TCP port.
};

/** @brief Timeout value meaning "block until completion or shutdown". */
constexpr uint32_t kNoTimeout = 0;

/**
 * @brief Blocking, bidirectional byte stream.
 *
 * @note Shutdown() is thread-safe and wakes operations blocked in other threads. The concurrency rules of the
 *       other methods are defined by each implementation.
 */
class ITransport {
public:
    /** @brief Destroys the transport; implementations release their resources. */
    virtual ~ITransport() = default;

    /**
     * @brief Connects to @p endpoint.
     * @param[in] endpoint Remote address.
     * @return SG_OK when connected; a failure code otherwise (implementation-defined).
     */
    virtual Status Connect(const Endpoint& endpoint) = 0;

    /**
     * @brief Sends every byte or fails. Blocks up to the transport's I/O timeout.
     * @param[in] data Bytes to send.
     * @param[in] size Number of bytes.
     * @retval SG_OK      All bytes were sent.
     * @retval SG_TIMEOUT The I/O timeout elapsed.
     * @retval SG_CLOSED  The transport has been shut down.
     * @return Another failure code on other errors. After any failure, part of the data may have been sent.
     */
    virtual Status Send(const uint8_t* data, size_t size) = 0;

    /**
     * @brief As Send, with an explicit timeout (kNoTimeout = wait indefinitely).
     * @param[in] data       Bytes to send.
     * @param[in] size       Number of bytes.
     * @param[in] timeout_ms Timeout in milliseconds, or #kNoTimeout.
     * @return As Send().
     */
    virtual Status SendFor(const uint8_t* data, size_t size, uint32_t timeout_ms) = 0;

    /**
     * @brief Receives between 1 and capacity bytes.
     * @param[out] buffer   Destination.
     * @param[in]  capacity Size of @p buffer in bytes.
     * @param[out] received Number of bytes stored in @p buffer.
     * @retval SG_OK      At least one byte was received.
     * @retval SG_CLOSED  Orderly end-of-stream, or the transport has been shut down.
     * @retval SG_TIMEOUT The I/O timeout elapsed.
     * @return Another failure code on other errors.
     */
    virtual Status Receive(uint8_t* buffer, size_t capacity, size_t* received) = 0;

    /**
     * @brief As Receive, with an explicit timeout (kNoTimeout = wait indefinitely).
     * @param[out] buffer     Destination.
     * @param[in]  capacity   Size of @p buffer in bytes.
     * @param[out] received   Number of bytes stored in @p buffer.
     * @param[in]  timeout_ms Timeout in milliseconds, or #kNoTimeout.
     * @return As Receive().
     */
    virtual Status ReceiveFor(uint8_t* buffer, size_t capacity, size_t* received, uint32_t timeout_ms) = 0;

    /**
     * @brief Wakes operations blocked in other threads; every later operation fails with SG_CLOSED.
     * @note Thread-safe.
     */
    virtual void Shutdown() noexcept = 0;

    /** @brief Shutdown + release of the underlying resources once no operation is in flight. */
    virtual void Close() noexcept = 0;

    /**
     * @brief Returns a printable address of the remote peer, for logging.
     * @return The peer address (format defined by the implementation).
     */
    virtual std::string PeerAddress() const = 0;
};

}  // namespace sg::net
