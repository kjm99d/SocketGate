// IOCP implementation of IIoService (Windows).
//
// Lifetime model: every overlapped operation embeds its OVERLAPPED in an
// object that holds a shared_ptr to the owning stream while the operation is
// pending. The kernel may therefore complete (or cancel) an operation at any
// time without the OVERLAPPED ever being freed underneath it.
//
// Listener sockets are only used and closed under listeners_mutex_, so a
// worker can never issue AcceptEx against a handle Stop() already closed.
#include "transport/io_service.h"

#include "sockgate_common/platform/socket.h"

#include <winsock2.h>
#include <mswsock.h>
#include <ws2tcpip.h>
#include <windows.h>

#include <algorithm>
#include <atomic>
#include <chrono>
#include <condition_variable>
#include <cstring>
#include <deque>
#include <mutex>
#include <thread>
#include <unordered_map>

namespace sg::server {
namespace {

constexpr ULONG_PTR kQuitKey = 1;
constexpr int kAcceptsPerListener = 8;
constexpr DWORD kAddressLength = sizeof(SOCKADDR_STORAGE) + 16;
constexpr auto kStopDrainTimeout = std::chrono::seconds(10);
constexpr DWORD kAcceptRetryDelayMs = 20;

enum class OpType { kAccept, kRead, kWrite, kTask };

struct IoOp {
    OVERLAPPED overlapped;
    OpType type;
    explicit IoOp(OpType t) : overlapped(), type(t) {}
    void Reset() { std::memset(&overlapped, 0, sizeof(overlapped)); }
};

class IocpService;
class IocpStream;

struct StreamOp : IoOp {
    explicit StreamOp(OpType t) : IoOp(t) {}
    std::shared_ptr<IocpStream> stream;  // keeps the stream (and this op) alive while pending
};

struct TaskOp : IoOp {
    explicit TaskOp(std::function<void()> f) : IoOp(OpType::kTask), fn(std::move(f)) {}
    std::function<void()> fn;
};

struct Listener;

struct AcceptOp : IoOp {
    AcceptOp() : IoOp(OpType::kAccept) {}
    Listener* listener = nullptr;
    SOCKET accept_socket = INVALID_SOCKET;
    uint8_t buffer[2 * kAddressLength] = {};
};

struct Listener {
    SOCKET socket = INVALID_SOCKET;
    int family = AF_INET;
    AcceptHandler on_accept;
    LPFN_ACCEPTEX accept_ex = nullptr;
    LPFN_GETACCEPTEXSOCKADDRS get_addrs = nullptr;
    std::vector<std::unique_ptr<AcceptOp>> ops;

    ~Listener()
    {
        if (socket != INVALID_SOCKET) closesocket(socket);
        for (auto& op : ops) {
            if (op->accept_socket != INVALID_SOCKET) closesocket(op->accept_socket);
        }
    }
};

using Callback = std::function<void()>;

void InvokeSafely(const Callback& cb) noexcept
{
    try {
        cb();
    } catch (...) {
        // A throwing user handler must not skip the remaining callbacks.
    }
}

void InvokeAll(std::vector<Callback>& callbacks) noexcept
{
    for (auto& cb : callbacks) InvokeSafely(cb);
    callbacks.clear();
}

class IocpStream final : public AsyncStream, public std::enable_shared_from_this<IocpStream> {
public:
    IocpStream(IocpService* service, SOCKET socket, uint64_t id, std::string peer, size_t read_buffer_size)
        : service_(service), socket_(socket), id_(id), peer_(std::move(peer)), read_buffer_(read_buffer_size)
    {
    }

    // Dropping the last reference closes the connection. Streams must not
    // outlive the IIoService that created them.
    ~IocpStream() override;

    Status AsyncRead(ReadHandler handler) override;
    Status AsyncWrite(std::vector<uint8_t> data, WriteHandler handler) override;
    void CloseAfterWrites() noexcept override;
    void Close() noexcept override;

    bool IsClosed() const noexcept override
    {
        std::lock_guard<std::mutex> lock(mutex_);
        return closed_;
    }
    uint64_t Id() const noexcept override { return id_; }
    const std::string& PeerAddress() const noexcept override { return peer_; }
    size_t PendingWriteBytes() const noexcept override
    {
        std::lock_guard<std::mutex> lock(mutex_);
        return pending_write_bytes_;
    }

    void OnReadComplete(bool ok, DWORD bytes);
    void OnWriteComplete(bool ok, DWORD bytes);

private:
    struct PendingWrite {
        std::vector<uint8_t> data;
        size_t offset = 0;
        WriteHandler handler;
    };

    // All *Locked helpers append callbacks to be invoked after the lock is released.
    bool StartReadLocked();
    void StartWriteLocked(std::vector<Callback>* deferred);
    void StartDrainLocked(std::vector<Callback>* deferred);
    void FinishGracefulLocked(std::vector<Callback>* deferred);
    void CloseLocked(std::vector<Callback>* deferred, Status reason);
    // Fails queued writes; keeps the front entry when a write is still in flight
    // (its cancelled completion fails it later).
    void FailQueuedWritesLocked(std::vector<Callback>* deferred, Status status);

    IocpService* service_;
    SOCKET socket_;
    const uint64_t id_;
    const std::string peer_;

    mutable std::mutex mutex_;
    bool closed_ = false;
    bool close_after_writes_ = false;
    bool send_shutdown_ = false;
    bool draining_ = false;  // internal read that discards input until EOF

    std::vector<uint8_t> read_buffer_;
    bool read_pending_ = false;
    ReadHandler read_handler_;
    StreamOp read_op_{OpType::kRead};

    std::deque<PendingWrite> write_queue_;
    bool write_in_flight_ = false;
    size_t pending_write_bytes_ = 0;
    StreamOp write_op_{OpType::kWrite};
};

class IocpService final : public IIoService {
public:
    IocpService() = default;
    ~IocpService() override { Stop(); }

    Status Start(const IoServiceOptions& options) override;
    Status Listen(const std::string& bind_address, uint16_t port, AcceptHandler on_accept,
                  uint16_t* bound_port) override;
    Status Post(std::function<void()> fn) override;
    void Stop() noexcept override;
    size_t StreamCount() const noexcept override
    {
        std::lock_guard<std::mutex> lock(streams_mutex_);
        return streams_.size();
    }

    void OpStarted() noexcept { outstanding_ops_.fetch_add(1, std::memory_order_acq_rel); }
    void OpFinished() noexcept
    {
        if (outstanding_ops_.fetch_sub(1, std::memory_order_acq_rel) == 1) {
            std::lock_guard<std::mutex> lock(ops_mutex_);
            ops_cv_.notify_all();
        }
    }

    void Unregister(uint64_t id)
    {
        std::lock_guard<std::mutex> lock(streams_mutex_);
        streams_.erase(id);
    }

    // Callbacks produced by API calls (Close, AsyncWrite, ...) never run on the
    // caller's thread: the caller may hold its own locks. They are posted to a
    // worker instead; inline execution is only the last resort after shutdown.
    void RunDeferred(std::vector<Callback> deferred) noexcept
    {
        if (deferred.empty()) return;
        auto shared = std::make_shared<std::vector<Callback>>(std::move(deferred));
        if (!PostInternal([shared]() { InvokeAll(*shared); }).ok()) InvokeAll(*shared);
    }

private:
    Status PostInternal(std::function<void()> fn);
    void WorkerLoop();
    void PostAcceptLocked(AcceptOp* op);
    void RetryAcceptLater(AcceptOp* op);
    void OnAcceptComplete(AcceptOp* op, bool ok);

    platform::NetworkRuntime net_;
    HANDLE iocp_ = nullptr;
    IoServiceOptions options_;
    std::vector<std::thread> workers_;
    std::atomic<int64_t> outstanding_ops_{0};
    std::atomic<bool> running_{false};
    std::atomic<bool> stopping_{false};
    std::atomic<uint64_t> next_stream_id_{1};

    std::mutex stop_mutex_;
    std::mutex ops_mutex_;
    std::condition_variable ops_cv_;

    std::mutex post_mutex_;
    bool quitting_ = false;  // guarded by post_mutex_

    std::mutex listeners_mutex_;
    std::vector<std::unique_ptr<Listener>> listeners_;

    mutable std::mutex streams_mutex_;
    std::unordered_map<uint64_t, std::weak_ptr<IocpStream>> streams_;
};

// ---------------------------------------------------------------------------
// IocpStream

IocpStream::~IocpStream()
{
    if (socket_ != INVALID_SOCKET) closesocket(socket_);
    service_->Unregister(id_);
}

bool IocpStream::StartReadLocked()
{
    read_op_.Reset();
    read_op_.stream = shared_from_this();
    WSABUF buf;
    buf.buf = reinterpret_cast<char*>(read_buffer_.data());
    buf.len = static_cast<ULONG>(read_buffer_.size());
    DWORD flags = 0;
    service_->OpStarted();
    if (WSARecv(socket_, &buf, 1, nullptr, &flags, &read_op_.overlapped, nullptr) == SOCKET_ERROR &&
        WSAGetLastError() != WSA_IO_PENDING) {
        service_->OpFinished();
        read_op_.stream.reset();
        return false;
    }
    return true;
}

Status IocpStream::AsyncRead(ReadHandler handler)
{
    if (!handler) return SG_INVALID_ARGUMENT;
    std::vector<Callback> deferred;
    Status result = OkStatus();
    {
        std::lock_guard<std::mutex> lock(mutex_);
        if (closed_ || draining_) return SG_CLOSED;
        if (read_pending_) return SG_INVALID_STATE;
        read_handler_ = std::move(handler);
        read_pending_ = true;
        if (!StartReadLocked()) {
            // Nothing was queued: fail synchronously without invoking the handler.
            read_pending_ = false;
            read_handler_ = nullptr;
            CloseLocked(&deferred, SG_NETWORK_ERROR);
            result = SG_NETWORK_ERROR;
        }
    }
    service_->RunDeferred(std::move(deferred));
    return result;
}

void IocpStream::StartDrainLocked(std::vector<Callback>* deferred)
{
    draining_ = true;
    read_pending_ = true;
    if (!StartReadLocked()) {
        read_pending_ = false;
        draining_ = false;
        CloseLocked(deferred, SG_CLOSED);
    }
}

void IocpStream::OnReadComplete(bool ok, DWORD bytes)
{
    std::vector<Callback> deferred;
    ReadHandler handler;
    std::shared_ptr<IocpStream> self;
    Status status = OkStatus();
    {
        std::lock_guard<std::mutex> lock(mutex_);
        self = std::move(read_op_.stream);
        read_pending_ = false;
        if (draining_) {
            // Graceful close: discard input until the peer's FIN (or an error).
            if (!closed_ && ok && bytes > 0) {
                StartDrainLocked(&deferred);
            } else {
                draining_ = false;
                CloseLocked(&deferred, SG_CLOSED);
            }
        } else {
            handler = std::move(read_handler_);
            read_handler_ = nullptr;
            if (closed_) {
                status = SG_CLOSED;
            } else if (!ok) {
                status = SG_NETWORK_ERROR;
            } else if (bytes == 0) {
                status = SG_CLOSED;  // orderly shutdown by the peer
            }
        }
    }
    InvokeAll(deferred);
    if (!handler) return;

    if (status.ok()) {
        InvokeSafely([&]() { handler(status, read_buffer_.data(), bytes); });
    } else {
        InvokeSafely([&]() { handler(status, nullptr, 0); });
    }

    // After a half-close, keep draining once the owner stops reading.
    {
        std::lock_guard<std::mutex> lock(mutex_);
        if (!closed_ && send_shutdown_ && !read_pending_ && !draining_) StartDrainLocked(&deferred);
    }
    InvokeAll(deferred);
}

Status IocpStream::AsyncWrite(std::vector<uint8_t> data, WriteHandler handler)
{
    if (data.empty()) return SG_INVALID_ARGUMENT;
    std::vector<Callback> deferred;
    {
        std::lock_guard<std::mutex> lock(mutex_);
        if (closed_ || close_after_writes_) return SG_CLOSED;
        pending_write_bytes_ += data.size();
        write_queue_.push_back(PendingWrite{std::move(data), 0, std::move(handler)});
        if (!write_in_flight_) StartWriteLocked(&deferred);
    }
    service_->RunDeferred(std::move(deferred));
    return OkStatus();
}

void IocpStream::StartWriteLocked(std::vector<Callback>* deferred)
{
    if (closed_ || write_queue_.empty()) return;
    PendingWrite& front = write_queue_.front();
    const size_t remaining = front.data.size() - front.offset;
    WSABUF buf;
    buf.buf = reinterpret_cast<char*>(front.data.data() + front.offset);
    buf.len = static_cast<ULONG>(std::min<size_t>(remaining, 1u << 30));

    write_op_.Reset();
    write_op_.stream = shared_from_this();
    write_in_flight_ = true;
    service_->OpStarted();
    if (WSASend(socket_, &buf, 1, nullptr, 0, &write_op_.overlapped, nullptr) == SOCKET_ERROR &&
        WSAGetLastError() != WSA_IO_PENDING) {
        service_->OpFinished();
        write_in_flight_ = false;
        write_op_.stream.reset();
        CloseLocked(deferred, SG_NETWORK_ERROR);
    }
}

void IocpStream::OnWriteComplete(bool ok, DWORD bytes)
{
    std::vector<Callback> deferred;
    std::shared_ptr<IocpStream> self;
    {
        std::lock_guard<std::mutex> lock(mutex_);
        self = std::move(write_op_.stream);
        write_in_flight_ = false;
        if (!ok || closed_ || write_queue_.empty()) {
            const Status failure = closed_ ? Status(SG_CLOSED) : Status(SG_NETWORK_ERROR);
            CloseLocked(&deferred, failure);
            FailQueuedWritesLocked(&deferred, failure);
        } else {
            PendingWrite& front = write_queue_.front();
            const size_t advanced = std::min<size_t>(bytes, front.data.size() - front.offset);
            front.offset += advanced;
            pending_write_bytes_ -= std::min(pending_write_bytes_, advanced);
            if (front.offset == front.data.size()) {
                if (front.handler) {
                    WriteHandler h = std::move(front.handler);
                    deferred.push_back([h = std::move(h)]() { h(OkStatus()); });
                }
                write_queue_.pop_front();
            }
            if (!write_queue_.empty()) {
                StartWriteLocked(&deferred);
            } else if (close_after_writes_) {
                FinishGracefulLocked(&deferred);
            }
        }
    }
    InvokeAll(deferred);
}

void IocpStream::FinishGracefulLocked(std::vector<Callback>* deferred)
{
    if (closed_ || send_shutdown_) return;
    send_shutdown_ = true;
    // Half-close: the peer receives FIN after every queued byte. Closing with
    // unread input would instead send RST and could destroy data in flight.
    shutdown(socket_, SD_SEND);
    if (!read_pending_) StartDrainLocked(deferred);
}

void IocpStream::CloseAfterWrites() noexcept
{
    std::vector<Callback> deferred;
    {
        std::lock_guard<std::mutex> lock(mutex_);
        if (closed_) return;
        close_after_writes_ = true;
        if (!write_in_flight_ && write_queue_.empty()) FinishGracefulLocked(&deferred);
    }
    service_->RunDeferred(std::move(deferred));
}

void IocpStream::Close() noexcept
{
    std::vector<Callback> deferred;
    {
        std::lock_guard<std::mutex> lock(mutex_);
        CloseLocked(&deferred, SG_CLOSED);
    }
    service_->RunDeferred(std::move(deferred));
}

void IocpStream::CloseLocked(std::vector<Callback>* deferred, Status reason)
{
    if (closed_) return;
    closed_ = true;
    if (socket_ != INVALID_SOCKET) {
        // Cancels pending overlapped operations; their completions report SG_CLOSED.
        closesocket(socket_);
        socket_ = INVALID_SOCKET;
    }
    FailQueuedWritesLocked(deferred, reason.ok() ? Status(SG_CLOSED) : reason);
    const uint64_t id = id_;
    IocpService* service = service_;
    deferred->push_back([service, id]() { service->Unregister(id); });
}

void IocpStream::FailQueuedWritesLocked(std::vector<Callback>* deferred, Status status)
{
    const size_t keep = write_in_flight_ ? 1 : 0;
    while (write_queue_.size() > keep) {
        PendingWrite w = std::move(write_queue_.back());
        write_queue_.pop_back();
        pending_write_bytes_ -= std::min(pending_write_bytes_, w.data.size() - w.offset);
        if (w.handler) {
            WriteHandler h = std::move(w.handler);
            deferred->push_back([h = std::move(h), status]() { h(status); });
        }
    }
}

// ---------------------------------------------------------------------------
// IocpService

Status IocpService::Start(const IoServiceOptions& options)
{
    std::lock_guard<std::mutex> stop_lock(stop_mutex_);
    if (running_.load()) return SG_INVALID_STATE;
    SG_TRY(net_.status());
    options_ = options;
    if (options_.read_buffer_size < 1024) options_.read_buffer_size = 1024;
    uint32_t threads = options_.worker_threads;
    if (threads == 0) threads = std::max(1u, std::thread::hardware_concurrency());
    threads = std::min(threads, 64u);

    iocp_ = CreateIoCompletionPort(INVALID_HANDLE_VALUE, nullptr, 0, 0);
    if (iocp_ == nullptr) return SG_NETWORK_ERROR;

    stopping_ = false;
    {
        std::lock_guard<std::mutex> lock(post_mutex_);
        quitting_ = false;
    }
    running_ = true;
    try {
        for (uint32_t i = 0; i < threads; ++i) workers_.emplace_back([this]() { WorkerLoop(); });
    } catch (...) {
        // Tear down the threads that did start.
        for (size_t i = 0; i < workers_.size(); ++i) PostQueuedCompletionStatus(iocp_, 0, kQuitKey, nullptr);
        for (auto& w : workers_) w.join();
        workers_.clear();
        CloseHandle(iocp_);
        iocp_ = nullptr;
        running_ = false;
        return SG_OUT_OF_MEMORY;
    }
    return OkStatus();
}

Status IocpService::Listen(const std::string& bind_address, uint16_t port, AcceptHandler on_accept,
                           uint16_t* bound_port)
{
    if (!running_.load() || stopping_.load()) return SG_INVALID_STATE;
    if (!on_accept) return SG_INVALID_ARGUMENT;

    std::vector<platform::SocketAddress> addresses;
    SG_TRY(platform::ResolveAddresses(bind_address, port, true, &addresses));

    auto listener = std::make_unique<Listener>();
    platform::NativeSocket native = platform::kInvalidSocket;
    SG_TRY(platform::CreateListener(addresses.front(), options_.listen_backlog, false, &native));
    listener->socket = static_cast<SOCKET>(native);  // closed by ~Listener on any failure below
    listener->family = addresses.front().Family();
    listener->on_accept = std::move(on_accept);

    GUID accept_ex_guid = WSAID_ACCEPTEX;
    GUID get_addrs_guid = WSAID_GETACCEPTEXSOCKADDRS;
    DWORD bytes = 0;
    if (WSAIoctl(listener->socket, SIO_GET_EXTENSION_FUNCTION_POINTER, &accept_ex_guid, sizeof(accept_ex_guid),
                 &listener->accept_ex, sizeof(listener->accept_ex), &bytes, nullptr, nullptr) != 0 ||
        WSAIoctl(listener->socket, SIO_GET_EXTENSION_FUNCTION_POINTER, &get_addrs_guid, sizeof(get_addrs_guid),
                 &listener->get_addrs, sizeof(listener->get_addrs), &bytes, nullptr, nullptr) != 0 ||
        CreateIoCompletionPort(reinterpret_cast<HANDLE>(listener->socket), iocp_, 0, 0) == nullptr) {
        return SG_NETWORK_ERROR;
    }

    if (bound_port != nullptr) {
        platform::SocketAddress local;
        SG_TRY(platform::GetLocalAddress(static_cast<platform::NativeSocket>(listener->socket), &local));
        *bound_port = local.Port();
    }

    std::lock_guard<std::mutex> lock(listeners_mutex_);
    if (stopping_.load()) return SG_INVALID_STATE;  // ~Listener closes the socket
    Listener* raw = listener.get();
    for (int i = 0; i < kAcceptsPerListener; ++i) {
        auto op = std::make_unique<AcceptOp>();
        op->listener = raw;
        raw->ops.push_back(std::move(op));
    }
    listeners_.push_back(std::move(listener));
    for (auto& op : raw->ops) PostAcceptLocked(op.get());
    return OkStatus();
}

void IocpService::PostAcceptLocked(AcceptOp* op)
{
    if (stopping_.load() || op->listener->socket == INVALID_SOCKET) return;
    platform::NativeSocket native = platform::kInvalidSocket;
    if (!platform::CreateTcpSocket(op->listener->family, false, &native).ok()) {
        RetryAcceptLater(op);
        return;
    }
    op->accept_socket = static_cast<SOCKET>(native);
    op->Reset();
    DWORD received = 0;
    OpStarted();
    if (!op->listener->accept_ex(op->listener->socket, op->accept_socket, op->buffer, 0, kAddressLength,
                                 kAddressLength, &received, &op->overlapped) &&
        WSAGetLastError() != ERROR_IO_PENDING) {
        OpFinished();
        closesocket(op->accept_socket);
        op->accept_socket = INVALID_SOCKET;
        RetryAcceptLater(op);
    }
}

void IocpService::RetryAcceptLater(AcceptOp* op)
{
    // Resource exhaustion (e.g. WSAENOBUFS): keep the accept slot alive by
    // retrying shortly instead of silently shrinking the accept pipeline.
    PostInternal([this, op]() {
        Sleep(kAcceptRetryDelayMs);
        std::lock_guard<std::mutex> lock(listeners_mutex_);
        PostAcceptLocked(op);
    }).IgnoreError();
}

void IocpService::OnAcceptComplete(AcceptOp* op, bool ok)
{
    SOCKET accepted = op->accept_socket;
    op->accept_socket = INVALID_SOCKET;

    std::unique_lock<std::mutex> lock(listeners_mutex_);
    Listener* listener = op->listener;
    if (!ok || stopping_.load() || listener->socket == INVALID_SOCKET) {
        if (accepted != INVALID_SOCKET) closesocket(accepted);
        PostAcceptLocked(op);  // no-op while stopping
        return;
    }

    std::string peer = "?";
    sockaddr* local_addr = nullptr;
    sockaddr* remote_addr = nullptr;
    int local_len = 0;
    int remote_len = 0;
    listener->get_addrs(op->buffer, 0, kAddressLength, kAddressLength, &local_addr, &local_len, &remote_addr,
                        &remote_len);
    if (remote_addr != nullptr && remote_len > 0 &&
        static_cast<size_t>(remote_len) <= sizeof(platform::SocketAddress::storage)) {
        platform::SocketAddress sa;
        std::memcpy(sa.storage, remote_addr, static_cast<size_t>(remote_len));
        sa.length = static_cast<uint32_t>(remote_len);
        peer = sa.ToString();
    }

    SOCKET listen_socket = listener->socket;
    const bool configured =
        setsockopt(accepted, SOL_SOCKET, SO_UPDATE_ACCEPT_CONTEXT, reinterpret_cast<const char*>(&listen_socket),
                   sizeof(listen_socket)) == 0 &&
        CreateIoCompletionPort(reinterpret_cast<HANDLE>(accepted), iocp_, 0, 0) != nullptr &&
        SetFileCompletionNotificationModes(reinterpret_cast<HANDLE>(accepted), FILE_SKIP_SET_EVENT_ON_HANDLE);

    // Keep the accept pipeline full before running user code.
    PostAcceptLocked(op);
    AcceptHandler on_accept = listener->on_accept;
    lock.unlock();

    if (!configured) {
        closesocket(accepted);
        return;
    }
    platform::SetTcpNoDelay(static_cast<platform::NativeSocket>(accepted), true).IgnoreError();

    std::shared_ptr<IocpStream> stream;
    try {
        stream = std::make_shared<IocpStream>(this, accepted, next_stream_id_.fetch_add(1), std::move(peer),
                                              options_.read_buffer_size);
    } catch (...) {
        closesocket(accepted);
        return;
    }
    {
        std::lock_guard<std::mutex> streams_lock(streams_mutex_);
        streams_[stream->Id()] = stream;
    }
    if (stopping_.load()) {
        stream->Close();
        return;
    }
    InvokeSafely([&]() { on_accept(stream); });
}

Status IocpService::Post(std::function<void()> fn)
{
    // External work is refused as soon as shutdown begins so that a task that
    // keeps re-posting itself cannot hold Stop() hostage.
    if (stopping_.load()) return SG_CLOSED;
    return PostInternal(std::move(fn));
}

Status IocpService::PostInternal(std::function<void()> fn)
{
    if (!fn) return SG_INVALID_ARGUMENT;
    std::lock_guard<std::mutex> lock(post_mutex_);
    if (!running_.load() || quitting_) return SG_CLOSED;
    auto* task = new (std::nothrow) TaskOp(std::move(fn));
    if (task == nullptr) return SG_OUT_OF_MEMORY;
    OpStarted();
    if (!PostQueuedCompletionStatus(iocp_, 0, 0, &task->overlapped)) {
        OpFinished();
        delete task;
        return SG_INTERNAL_ERROR;
    }
    return OkStatus();
}

void IocpService::WorkerLoop()
{
    for (;;) {
        DWORD bytes = 0;
        ULONG_PTR key = 0;
        LPOVERLAPPED overlapped = nullptr;
        const BOOL ok = GetQueuedCompletionStatus(iocp_, &bytes, &key, &overlapped, INFINITE);
        if (overlapped == nullptr) {
            if (key == kQuitKey) return;
            if (!ok && GetLastError() == ERROR_ABANDONED_WAIT_0) return;  // port closed
            continue;
        }
        IoOp* op = CONTAINING_RECORD(overlapped, IoOp, overlapped);
        switch (op->type) {
        case OpType::kRead: {
            std::shared_ptr<IocpStream> stream = static_cast<StreamOp*>(op)->stream;
            if (stream) stream->OnReadComplete(ok != FALSE, bytes);
            break;
        }
        case OpType::kWrite: {
            std::shared_ptr<IocpStream> stream = static_cast<StreamOp*>(op)->stream;
            if (stream) stream->OnWriteComplete(ok != FALSE, bytes);
            break;
        }
        case OpType::kAccept:
            OnAcceptComplete(static_cast<AcceptOp*>(op), ok != FALSE);
            break;
        case OpType::kTask: {
            std::unique_ptr<TaskOp> task(static_cast<TaskOp*>(op));
            InvokeSafely(task->fn);
            break;
        }
        }
        OpFinished();
    }
}

void IocpService::Stop() noexcept
{
    std::lock_guard<std::mutex> stop_lock(stop_mutex_);
    if (!running_.load()) return;
    const std::thread::id self = std::this_thread::get_id();
    for (const auto& w : workers_) {
        if (w.get_id() == self) return;  // contract violation: never stop from a worker
    }
    stopping_ = true;

    {
        std::lock_guard<std::mutex> lock(listeners_mutex_);
        for (auto& l : listeners_) {
            if (l->socket != INVALID_SOCKET) {
                closesocket(l->socket);  // pending AcceptEx complete with an error
                l->socket = INVALID_SOCKET;
            }
        }
    }

    std::vector<std::shared_ptr<IocpStream>> streams;
    {
        std::lock_guard<std::mutex> lock(streams_mutex_);
        for (auto& entry : streams_) {
            if (auto s = entry.second.lock()) streams.push_back(std::move(s));
        }
    }
    for (auto& s : streams) s->Close();
    streams.clear();

    // Wait for every pending operation (I/O and internal tasks) to drain.
    bool drained;
    {
        std::unique_lock<std::mutex> lock(ops_mutex_);
        drained = ops_cv_.wait_for(lock, kStopDrainTimeout, [this]() { return outstanding_ops_.load() <= 0; });
    }

    {
        // Tasks queued before the quit packets still run (the port is FIFO);
        // later posts are refused so nothing is stranded in the port.
        std::lock_guard<std::mutex> lock(post_mutex_);
        quitting_ = true;
        for (size_t i = 0; i < workers_.size(); ++i) PostQueuedCompletionStatus(iocp_, 0, kQuitKey, nullptr);
    }
    for (auto& w : workers_) {
        if (w.joinable()) w.join();
    }
    workers_.clear();

    {
        std::lock_guard<std::mutex> lock(listeners_mutex_);
        if (drained) {
            listeners_.clear();
        } else {
            // Operations are still owned by the kernel: freeing their OVERLAPPED
            // buffers would be a use-after-free. Leak deliberately (fatal-path only).
            for (auto& l : listeners_) (void)l.release();
            listeners_.clear();
        }
    }
    {
        std::lock_guard<std::mutex> lock(streams_mutex_);
        streams_.clear();
    }
    if (drained) CloseHandle(iocp_);
    iocp_ = nullptr;
    {
        std::lock_guard<std::mutex> lock(post_mutex_);
        running_ = false;
    }
}

}  // namespace

std::unique_ptr<IIoService> CreateIoService() { return std::make_unique<IocpService>(); }

}  // namespace sg::server
