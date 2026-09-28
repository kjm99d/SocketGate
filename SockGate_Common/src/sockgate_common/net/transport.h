// Byte-stream transport abstraction used by the client (and by tests through
// an in-memory implementation). TLS runs on top of an ITransport via memory
// BIOs, so this interface carries ciphertext only.
#pragma once

#include "sockgate_common/core/status.h"

#include <cstddef>
#include <cstdint>
#include <string>

namespace sg::net {

struct Endpoint {
    std::string host;  // DNS name, IPv4 literal or IPv6 literal (without brackets)
    uint16_t port = 0;
};

// Timeout value meaning "block until completion or shutdown".
constexpr uint32_t kNoTimeout = 0;

class ITransport {
public:
    virtual ~ITransport() = default;

    virtual Status Connect(const Endpoint& endpoint) = 0;

    // Sends every byte or fails. Blocks up to the transport's I/O timeout.
    virtual Status Send(const uint8_t* data, size_t size) = 0;

    // Receives between 1 and capacity bytes. Returns SG_CLOSED on orderly
    // end-of-stream and SG_TIMEOUT when the I/O timeout elapses.
    virtual Status Receive(uint8_t* buffer, size_t capacity, size_t* received) = 0;

    // As Receive, with an explicit timeout (kNoTimeout = wait indefinitely).
    virtual Status ReceiveFor(uint8_t* buffer, size_t capacity, size_t* received, uint32_t timeout_ms) = 0;

    // Thread-safe. Wakes operations blocked in other threads; every later
    // operation fails with SG_CLOSED.
    virtual void Shutdown() noexcept = 0;

    // Shutdown + release of the underlying resources once no operation is in flight.
    virtual void Close() noexcept = 0;

    virtual std::string PeerAddress() const = 0;
};

}  // namespace sg::net
