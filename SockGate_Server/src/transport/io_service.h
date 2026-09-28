#pragma once
/**
 * @file
 * @brief Completion-style asynchronous I/O abstraction for the server.
 *
 * Windows implements it with IOCP (AcceptEx/WSARecv/WSASend), Linux with
 * epoll (EPOLLONESHOT, non-blocking sockets). Server core code only sees this
 * interface and never includes OS headers.
 *
 * Threading contract:
 *  - Handlers run on I/O worker threads, never while the stream's internal
 *    lock is held, so they may call back into the stream. Exceptions, where
 *    a callback runs inline on another thread (still outside the stream
 *    lock, but possibly while the caller holds locks of its own): when an
 *    API call (Close(), AsyncWrite(), ...) cannot post it to a worker
 *    because the service is stopping or stopped (IOCP also when queueing
 *    fails for lack of memory or a port error), it runs on the calling
 *    thread; on Linux, tasks still queued when the workers exited run on
 *    the thread calling Stop().
 *  - At most one read may be outstanding per stream; the connection issues
 *    the next read after it finished processing the previous one, which
 *    preserves per-connection ordering and provides backpressure.
 *  - Writes are queued and completed in order.
 *  - After Close(), pending handlers complete with SG_CLOSED exactly once.
 */

#include "sockgate_common/core/status.h"

#include <cstddef>
#include <cstdint>
#include <functional>
#include <memory>
#include <string>
#include <vector>

namespace sg::server {

/**
 * @brief An accepted TCP connection with asynchronous read and write.
 *
 * All methods are thread-safe. Dropping the last reference closes the connection, but while I/O is pending (a read,
 * queued writes, or the drain of a graceful close) the stream keeps itself open until that I/O completes, Close() is
 * called, or IIoService::Stop() runs - so dropping the owner's reference never cuts queued writes short. To abandon a
 * stream, call Close(). A stream must not outlive the IIoService that created it.
 */
class AsyncStream {
public:
    /**
     * @brief Read completion: OK with the received bytes, SG_CLOSED on orderly shutdown by the peer or after
     *        Close(), SG_NETWORK_ERROR on errors (then `data` is null and `size` 0).
     *
     * `data` points into the stream's read buffer and is valid only during the call.
     */
    using ReadHandler = std::function<void(Status status, const uint8_t* data, size_t size)>;
    /** @brief Write completion: OK once the data was fully handed to the OS, otherwise the failure status. */
    using WriteHandler = std::function<void(Status status)>;

    virtual ~AsyncStream() = default;

    /**
     * @brief Starts one read.
     *
     * Returns SG_INVALID_STATE if a read is already pending
     * and SG_CLOSED if the stream is closed (handler is not invoked then).
     *
     * @param[in] handler Completion handler; not invoked if this returns an error.
     * @retval SG_OK               Read started.
     * @retval SG_INVALID_STATE    A read is already pending.
     * @retval SG_CLOSED           The stream is closed, or a graceful close already shut down sending and
     *                             discards input.
     * @retval SG_NETWORK_ERROR    The read could not be started; the stream is closed.
     * @retval SG_INVALID_ARGUMENT @p handler is empty.
     */
    virtual Status AsyncRead(ReadHandler handler) = 0;

    /**
     * @brief Queues data for transmission.
     *
     * The optional handler runs once the data
     * was fully handed to the OS (or with an error status). A failure to send closes the stream.
     *
     * @param[in] data    Bytes to send (moved in); must not be empty.
     * @param[in] handler Optional completion handler.
     * @retval SG_OK               Queued.
     * @retval SG_CLOSED           The stream is closed or CloseAfterWrites() was called.
     * @retval SG_INVALID_ARGUMENT @p data is empty.
     */
    virtual Status AsyncWrite(std::vector<uint8_t> data, WriteHandler handler) = 0;

    /**
     * @brief Graceful close.
     *
     * Refuses new writes; once every queued byte was handed to
     * the OS the send direction is shut down (FIN) and remaining input is
     * discarded until the peer closes, then the stream closes. Closing with
     * unread input would make the OS send RST and could destroy the queued
     * response in flight. The owner must bound this phase with its own
     * timeout by calling Close(), so it keeps a reference until then.
     */
    virtual void CloseAfterWrites() noexcept = 0;

    /** @brief Immediately closes the socket and cancels pending operations. Idempotent. */
    virtual void Close() noexcept = 0;

    /**
     * @brief Tells whether the stream is closed.
     * @return True once closed (by Close(), an error or the end of a graceful close).
     */
    virtual bool IsClosed() const noexcept = 0;
    /** @brief Stream identifier. @return An id unique within the creating IIoService. */
    virtual uint64_t Id() const noexcept = 0;
    /** @brief Peer address. @return The peer address as text, fixed at accept. */
    virtual const std::string& PeerAddress() const noexcept = 0;
    /** @brief Pending output. @return Bytes queued for writing that were not yet handed to the OS. */
    virtual size_t PendingWriteBytes() const noexcept = 0;
};

/**
 * @brief Called on a worker thread for each accepted stream; dropping the last reference closes the stream.
 */
using AcceptHandler = std::function<void(std::shared_ptr<AsyncStream> stream)>;

/** @brief Options of IIoService::Start(). */
struct IoServiceOptions {
    uint32_t worker_threads = 0;       ///< 0 = hardware concurrency (clamped to [1, 64]).
    uint32_t read_buffer_size = 16384; ///< Bytes per outstanding read (at least 1024).
    int listen_backlog = 0;            ///< 0 = SOMAXCONN.
};

/**
 * @brief Platform I/O service: worker threads, listeners and streams.
 *
 * @note All methods are thread-safe. Stop() must not be called from a worker thread.
 */
class IIoService {
public:
    virtual ~IIoService() = default;

    /**
     * @brief Starts the worker threads.
     * @param[in] options Options (copied).
     * @retval SG_OK            Started.
     * @retval SG_INVALID_STATE Already running.
     * @retval SG_NETWORK_ERROR The completion port / epoll instance cannot be created.
     * @retval SG_OUT_OF_MEMORY The worker threads cannot be created.
     * @retval other            Network runtime initialization failure (Windows).
     */
    virtual Status Start(const IoServiceOptions& options) = 0;

    /**
     * @brief Binds and listens; on_accept runs on a worker thread for each accepted stream.
     *
     * Listens on the first address @p bind_address resolves to.
     *
     * @param[in]  bind_address Address to bind.
     * @param[in]  port         Port; 0 lets the OS choose.
     * @param[in]  on_accept    Accept handler; must not be empty.
     * @param[out] bound_port   Optional; receives the bound port.
     * @retval SG_OK               Listening.
     * @retval SG_INVALID_STATE    Not started, or stopping.
     * @retval SG_INVALID_ARGUMENT @p on_accept is empty.
     * @retval other               Address resolution, socket or listen failure (e.g. SG_NETWORK_ERROR).
     */
    virtual Status Listen(const std::string& bind_address, uint16_t port, AcceptHandler on_accept,
                          uint16_t* bound_port) = 0;

    /**
     * @brief Runs fn on a worker thread. Refused with SG_CLOSED once Stop() began.
     * @param[in] fn Task.
     * @retval SG_OK               Queued.
     * @retval SG_CLOSED           Stopping or not running.
     * @retval SG_INVALID_ARGUMENT @p fn is empty.
     * @retval other               Queueing failure (Windows: SG_OUT_OF_MEMORY, SG_INTERNAL_ERROR).
     */
    virtual Status Post(std::function<void()> fn) = 0;

    /**
     * @brief Stops the service.
     *
     * Stops accepting, closes every stream, waits for outstanding operations
     * (IOCP: at most 10 s) and joins the worker threads. Idempotent and safe to call concurrently;
     * must not be called from a worker thread (such a call returns without stopping).
     */
    virtual void Stop() noexcept = 0;

    /**
     * @brief Number of live streams.
     * @return Streams still registered with this service (they are unregistered shortly after they close).
     */
    virtual size_t StreamCount() const noexcept = 0;
};

/**
 * @brief Creates the platform implementation (IOCP on Windows, epoll on Linux).
 * @return A service that is not started yet.
 */
std::unique_ptr<IIoService> CreateIoService();

}  // namespace sg::server
