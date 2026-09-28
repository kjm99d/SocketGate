// Completion-style asynchronous I/O abstraction for the server.
//
// Windows implements it with IOCP (AcceptEx/WSARecv/WSASend), Linux with
// epoll (EPOLLONESHOT, non-blocking sockets). Server core code only sees this
// interface and never includes OS headers.
//
// Threading contract:
//  - Handlers run on I/O worker threads, never while the stream's internal
//    lock is held, so they may call back into the stream.
//  - At most one read may be outstanding per stream; the connection issues
//    the next read after it finished processing the previous one, which
//    preserves per-connection ordering and provides backpressure.
//  - Writes are queued and completed in order.
//  - After Close(), pending handlers complete with SG_CLOSED exactly once.
#pragma once

#include "sockgate_common/core/status.h"

#include <cstddef>
#include <cstdint>
#include <functional>
#include <memory>
#include <string>
#include <vector>

namespace sg::server {

class AsyncStream {
public:
    using ReadHandler = std::function<void(Status status, const uint8_t* data, size_t size)>;
    using WriteHandler = std::function<void(Status status)>;

    virtual ~AsyncStream() = default;

    // Starts one read. Returns SG_INVALID_STATE if a read is already pending
    // and SG_CLOSED if the stream is closed (handler is not invoked then).
    virtual Status AsyncRead(ReadHandler handler) = 0;

    // Queues data for transmission. The optional handler runs once the data
    // was fully handed to the OS (or with an error status).
    virtual Status AsyncWrite(std::vector<uint8_t> data, WriteHandler handler) = 0;

    // Stops accepting new writes and closes once queued data has been sent
    // (bounded by the service's shutdown behaviour). Used for graceful close.
    virtual void CloseAfterWrites() noexcept = 0;

    // Immediately closes the socket and cancels pending operations. Idempotent.
    virtual void Close() noexcept = 0;

    virtual bool IsClosed() const noexcept = 0;
    virtual uint64_t Id() const noexcept = 0;
    virtual const std::string& PeerAddress() const noexcept = 0;
    virtual size_t PendingWriteBytes() const noexcept = 0;
};

using AcceptHandler = std::function<void(std::shared_ptr<AsyncStream> stream)>;

struct IoServiceOptions {
    uint32_t worker_threads = 0;       // 0 = hardware concurrency (clamped to [1, 64])
    uint32_t read_buffer_size = 16384; // bytes per outstanding read
    int listen_backlog = 0;            // 0 = SOMAXCONN
};

class IIoService {
public:
    virtual ~IIoService() = default;

    virtual Status Start(const IoServiceOptions& options) = 0;

    // Binds and listens; on_accept runs on a worker thread for each accepted stream.
    virtual Status Listen(const std::string& bind_address, uint16_t port, AcceptHandler on_accept,
                          uint16_t* bound_port) = 0;

    // Runs fn on a worker thread.
    virtual Status Post(std::function<void()> fn) = 0;

    // Stops accepting, closes every stream, waits for outstanding operations
    // and joins the worker threads. Must not be called from a worker thread.
    virtual void Stop() noexcept = 0;

    virtual size_t StreamCount() const noexcept = 0;
};

// Creates the platform implementation (IOCP on Windows, epoll on Linux).
std::unique_ptr<IIoService> CreateIoService();

}  // namespace sg::server
