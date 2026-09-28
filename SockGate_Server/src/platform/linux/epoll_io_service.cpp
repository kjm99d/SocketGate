// epoll implementation of IIoService (Linux).
//
// Streams are registered with EPOLLONESHOT so that one stream is never
// processed by two workers at once, and are identified in epoll by a 64-bit
// id (not a pointer) looked up in a registry; a stale event for a closed
// stream therefore finds nothing instead of touching freed memory. All
// syscalls on a stream's fd happen under the stream mutex, so a closed fd
// number that the kernel reuses can never be read or written by mistake.
#include "transport/io_service.h"

#include "sockgate_common/platform/socket.h"

#include <cerrno>
#include <cstring>
#include <deque>
#include <mutex>
#include <netinet/in.h>
#include <sys/epoll.h>
#include <sys/eventfd.h>
#include <sys/socket.h>
#include <thread>
#include <unistd.h>
#include <unordered_map>
#include <atomic>
#include <algorithm>

namespace sg::server {
namespace {

constexpr uint64_t kWakeTag = 0;
constexpr uint64_t kListenerTag = 1ULL << 63;
constexpr int kMaxEvents = 64;
constexpr int kMaxAcceptsPerWake = 64;

using Callback = std::function<void()>;

class EpollService;

class EpollStream final : public AsyncStream, public std::enable_shared_from_this<EpollStream> {
public:
    EpollStream(EpollService* service, int fd, uint64_t id, std::string peer, size_t read_buffer_size)
        : service_(service), fd_(fd), id_(id), peer_(std::move(peer)), read_buffer_(read_buffer_size)
    {
    }

    // Dropping the last reference closes the connection. Streams must not
    // outlive the IIoService that created them.
    ~EpollStream() override;

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

    Status Register(int epfd);
    void OnEvent(uint32_t events);

private:
    struct PendingWrite {
        std::vector<uint8_t> data;
        size_t offset = 0;
        WriteHandler handler;
    };

    void UpdateInterestLocked(std::vector<Callback>* deferred);
    void CloseLocked(std::vector<Callback>* deferred, Status reason);
    void FailWritesLocked(std::vector<Callback>* deferred, Status status);

    EpollService* service_;
    int fd_;
    int epfd_ = -1;
    const uint64_t id_;
    const std::string peer_;

    mutable std::mutex mutex_;
    bool closed_ = false;
    bool close_after_writes_ = false;

    std::vector<uint8_t> read_buffer_;
    bool read_pending_ = false;
    ReadHandler read_handler_;

    std::deque<PendingWrite> write_queue_;
    size_t pending_write_bytes_ = 0;
};

struct Listener {
    int fd = -1;
    uint64_t tag = 0;
    AcceptHandler on_accept;
};

class EpollService final : public IIoService {
public:
    EpollService() = default;
    ~EpollService() override { Stop(); }

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

    void Unregister(uint64_t id)
    {
        std::lock_guard<std::mutex> lock(streams_mutex_);
        streams_.erase(id);
    }

    // See the IOCP implementation: API-triggered callbacks run on a worker.
    void RunDeferred(std::vector<Callback> deferred) noexcept
    {
        if (deferred.empty()) return;
        auto shared = std::make_shared<std::vector<Callback>>(std::move(deferred));
        if (!Post([shared]() { for (auto& cb : *shared) cb(); }).ok()) {
            for (auto& cb : *shared) cb();
        }
    }

private:
    void WorkerLoop();
    void OnWake();
    void OnListenerEvent(Listener* listener);
    void ArmWake();
    void ArmListener(Listener* listener);

    platform::NetworkRuntime net_;
    IoServiceOptions options_;
    int epfd_ = -1;
    int wake_fd_ = -1;
    std::vector<std::thread> workers_;
    std::atomic<bool> running_{false};
    std::atomic<bool> stopping_{false};
    std::atomic<uint64_t> next_stream_id_{1};

    std::mutex post_mutex_;
    std::deque<std::function<void()>> tasks_;  // guarded by post_mutex_
    bool quitting_ = false;                    // guarded by post_mutex_

    std::mutex listeners_mutex_;
    std::vector<std::unique_ptr<Listener>> listeners_;

    mutable std::mutex streams_mutex_;
    std::unordered_map<uint64_t, std::weak_ptr<EpollStream>> streams_;
};

// ---------------------------------------------------------------------------
// EpollStream

EpollStream::~EpollStream()
{
    if (fd_ >= 0) ::close(fd_);  // closing also removes the fd from the epoll set
    service_->Unregister(id_);
}

Status EpollStream::Register(int epfd)
{
    std::lock_guard<std::mutex> lock(mutex_);
    epfd_ = epfd;
    epoll_event ev;
    std::memset(&ev, 0, sizeof(ev));
    ev.events = EPOLLONESHOT | EPOLLRDHUP;  // not armed for I/O until a read/write is requested
    ev.data.u64 = id_;
    return ::epoll_ctl(epfd_, EPOLL_CTL_ADD, fd_, &ev) == 0 ? OkStatus() : Status(SG_NETWORK_ERROR);
}

void EpollStream::UpdateInterestLocked(std::vector<Callback>* deferred)
{
    if (closed_) return;
    uint32_t events = EPOLLONESHOT | EPOLLRDHUP;
    if (read_pending_) events |= EPOLLIN;
    if (!write_queue_.empty()) events |= EPOLLOUT;
    if ((events & (EPOLLIN | EPOLLOUT)) == 0) return;
    epoll_event ev;
    std::memset(&ev, 0, sizeof(ev));
    ev.events = events;
    ev.data.u64 = id_;
    if (::epoll_ctl(epfd_, EPOLL_CTL_MOD, fd_, &ev) != 0) CloseLocked(deferred, SG_NETWORK_ERROR);
}

Status EpollStream::AsyncRead(ReadHandler handler)
{
    if (!handler) return SG_INVALID_ARGUMENT;
    std::vector<Callback> deferred;
    Status result = OkStatus();
    {
        std::lock_guard<std::mutex> lock(mutex_);
        if (closed_) return SG_CLOSED;
        if (read_pending_) return SG_INVALID_STATE;
        read_handler_ = std::move(handler);
        read_pending_ = true;
        UpdateInterestLocked(&deferred);
        if (closed_) result = SG_NETWORK_ERROR;
    }
    service_->RunDeferred(std::move(deferred));
    return result;
}

Status EpollStream::AsyncWrite(std::vector<uint8_t> data, WriteHandler handler)
{
    if (data.empty()) return SG_INVALID_ARGUMENT;
    std::vector<Callback> deferred;
    {
        std::lock_guard<std::mutex> lock(mutex_);
        if (closed_ || close_after_writes_) return SG_CLOSED;
        pending_write_bytes_ += data.size();
        write_queue_.push_back(PendingWrite{std::move(data), 0, std::move(handler)});
        if (write_queue_.size() == 1) UpdateInterestLocked(&deferred);
    }
    service_->RunDeferred(std::move(deferred));
    return OkStatus();
}

void EpollStream::OnEvent(uint32_t events)
{
    std::vector<Callback> deferred;
    std::shared_ptr<EpollStream> self = shared_from_this();
    {
        std::lock_guard<std::mutex> lock(mutex_);
        if (closed_) return;

        const bool error = (events & EPOLLERR) != 0;

        if (read_pending_ && (events & (EPOLLIN | EPOLLHUP | EPOLLRDHUP | EPOLLERR)) != 0) {
            ssize_t n;
            do {
                n = ::recv(fd_, read_buffer_.data(), read_buffer_.size(), 0);
            } while (n < 0 && errno == EINTR);
            if (n > 0 || n == 0 || (errno != EAGAIN && errno != EWOULDBLOCK)) {
                ReadHandler h = std::move(read_handler_);
                read_handler_ = nullptr;
                read_pending_ = false;
                if (n > 0) {
                    const size_t size = static_cast<size_t>(n);
                    uint8_t* data = read_buffer_.data();
                    deferred.push_back([h = std::move(h), data, size]() { h(OkStatus(), data, size); });
                } else {
                    const Status st = n == 0 ? Status(SG_CLOSED) : Status(SG_NETWORK_ERROR);
                    deferred.push_back([h = std::move(h), st]() { h(st, nullptr, 0); });
                }
            }
        }

        if (!write_queue_.empty() && (events & (EPOLLOUT | EPOLLHUP | EPOLLERR)) != 0) {
            while (!write_queue_.empty()) {
                PendingWrite& front = write_queue_.front();
                ssize_t n;
                do {
                    n = ::send(fd_, front.data.data() + front.offset, front.data.size() - front.offset, MSG_NOSIGNAL);
                } while (n < 0 && errno == EINTR);
                if (n < 0) {
                    if (errno == EAGAIN || errno == EWOULDBLOCK) break;
                    CloseLocked(&deferred, SG_NETWORK_ERROR);
                    break;
                }
                front.offset += static_cast<size_t>(n);
                pending_write_bytes_ -= static_cast<size_t>(n);
                if (front.offset == front.data.size()) {
                    if (front.handler) {
                        WriteHandler h = std::move(front.handler);
                        deferred.push_back([h = std::move(h)]() { h(OkStatus()); });
                    }
                    write_queue_.pop_front();
                }
            }
        }

        if (!closed_ && error && !read_pending_ && write_queue_.empty()) CloseLocked(&deferred, SG_NETWORK_ERROR);
        if (!closed_ && close_after_writes_ && write_queue_.empty()) CloseLocked(&deferred, SG_CLOSED);
        UpdateInterestLocked(&deferred);
    }
    // Event-driven callbacks run inline on this worker thread.
    for (auto& cb : deferred) cb();
}

void EpollStream::CloseAfterWrites() noexcept
{
    std::vector<Callback> deferred;
    {
        std::lock_guard<std::mutex> lock(mutex_);
        if (closed_) return;
        close_after_writes_ = true;
        if (write_queue_.empty()) CloseLocked(&deferred, SG_CLOSED);
    }
    service_->RunDeferred(std::move(deferred));
}

void EpollStream::Close() noexcept
{
    std::vector<Callback> deferred;
    {
        std::lock_guard<std::mutex> lock(mutex_);
        CloseLocked(&deferred, SG_CLOSED);
    }
    service_->RunDeferred(std::move(deferred));
}

void EpollStream::FailWritesLocked(std::vector<Callback>* deferred, Status status)
{
    while (!write_queue_.empty()) {
        PendingWrite w = std::move(write_queue_.front());
        write_queue_.pop_front();
        if (w.handler) {
            WriteHandler h = std::move(w.handler);
            deferred->push_back([h = std::move(h), status]() { h(status); });
        }
    }
    pending_write_bytes_ = 0;
}

void EpollStream::CloseLocked(std::vector<Callback>* deferred, Status reason)
{
    if (closed_) return;
    closed_ = true;
    if (fd_ >= 0) {
        if (epfd_ >= 0) ::epoll_ctl(epfd_, EPOLL_CTL_DEL, fd_, nullptr);
        ::close(fd_);
        fd_ = -1;
    }
    if (read_pending_) {
        ReadHandler h = std::move(read_handler_);
        read_handler_ = nullptr;
        read_pending_ = false;
        const Status st = reason.ok() ? Status(SG_CLOSED) : reason;
        deferred->push_back([h = std::move(h), st]() { h(st, nullptr, 0); });
    }
    FailWritesLocked(deferred, reason.ok() ? Status(SG_CLOSED) : reason);
    const uint64_t id = id_;
    EpollService* service = service_;
    deferred->push_back([service, id]() { service->Unregister(id); });
}

// ---------------------------------------------------------------------------
// EpollService

Status EpollService::Start(const IoServiceOptions& options)
{
    if (running_.load()) return SG_INVALID_STATE;
    options_ = options;
    if (options_.read_buffer_size < 1024) options_.read_buffer_size = 1024;
    uint32_t threads = options_.worker_threads;
    if (threads == 0) threads = std::max(1u, std::thread::hardware_concurrency());
    threads = std::min(threads, 64u);

    epfd_ = ::epoll_create1(EPOLL_CLOEXEC);
    if (epfd_ < 0) return SG_NETWORK_ERROR;
    wake_fd_ = ::eventfd(0, EFD_NONBLOCK | EFD_CLOEXEC);
    if (wake_fd_ < 0) {
        ::close(epfd_);
        epfd_ = -1;
        return SG_NETWORK_ERROR;
    }
    epoll_event ev;
    std::memset(&ev, 0, sizeof(ev));
    ev.events = EPOLLIN | EPOLLONESHOT;
    ev.data.u64 = kWakeTag;
    if (::epoll_ctl(epfd_, EPOLL_CTL_ADD, wake_fd_, &ev) != 0) {
        ::close(wake_fd_);
        ::close(epfd_);
        wake_fd_ = epfd_ = -1;
        return SG_NETWORK_ERROR;
    }

    stopping_ = false;
    {
        std::lock_guard<std::mutex> lock(post_mutex_);
        quitting_ = false;
    }
    running_ = true;
    try {
        for (uint32_t i = 0; i < threads; ++i) workers_.emplace_back([this]() { WorkerLoop(); });
    } catch (...) {
        Stop();
        return SG_OUT_OF_MEMORY;
    }
    return OkStatus();
}

void EpollService::ArmWake()
{
    epoll_event ev;
    std::memset(&ev, 0, sizeof(ev));
    ev.events = EPOLLIN | EPOLLONESHOT;
    ev.data.u64 = kWakeTag;
    ::epoll_ctl(epfd_, EPOLL_CTL_MOD, wake_fd_, &ev);
}

void EpollService::ArmListener(Listener* listener)
{
    epoll_event ev;
    std::memset(&ev, 0, sizeof(ev));
    ev.events = EPOLLIN | EPOLLONESHOT;
    ev.data.u64 = listener->tag;
    ::epoll_ctl(epfd_, EPOLL_CTL_MOD, listener->fd, &ev);
}

Status EpollService::Listen(const std::string& bind_address, uint16_t port, AcceptHandler on_accept,
                            uint16_t* bound_port)
{
    if (!running_.load() || stopping_.load()) return SG_INVALID_STATE;
    if (!on_accept) return SG_INVALID_ARGUMENT;

    std::vector<platform::SocketAddress> addresses;
    SG_TRY(platform::ResolveAddresses(bind_address, port, true, &addresses));
    platform::NativeSocket native = platform::kInvalidSocket;
    SG_TRY(platform::CreateListener(addresses.front(), options_.listen_backlog, true, &native));

    auto listener = std::make_unique<Listener>();
    listener->fd = static_cast<int>(native);
    listener->on_accept = std::move(on_accept);

    if (bound_port != nullptr) {
        platform::SocketAddress local;
        if (!platform::GetLocalAddress(native, &local).ok()) {
            ::close(listener->fd);
            return SG_NETWORK_ERROR;
        }
        *bound_port = local.Port();
    }

    std::lock_guard<std::mutex> lock(listeners_mutex_);
    listener->tag = kListenerTag | static_cast<uint64_t>(listeners_.size());
    epoll_event ev;
    std::memset(&ev, 0, sizeof(ev));
    ev.events = EPOLLIN | EPOLLONESHOT;
    ev.data.u64 = listener->tag;
    if (::epoll_ctl(epfd_, EPOLL_CTL_ADD, listener->fd, &ev) != 0) {
        ::close(listener->fd);
        return SG_NETWORK_ERROR;
    }
    listeners_.push_back(std::move(listener));
    return OkStatus();
}

void EpollService::OnListenerEvent(Listener* listener)
{
    std::vector<std::shared_ptr<EpollStream>> accepted;
    bool exhausted = false;
    for (int i = 0; i < kMaxAcceptsPerWake && !stopping_.load(); ++i) {
        sockaddr_storage peer_addr;
        socklen_t peer_len = sizeof(peer_addr);
        const int fd = ::accept4(listener->fd, reinterpret_cast<sockaddr*>(&peer_addr), &peer_len,
                                 SOCK_NONBLOCK | SOCK_CLOEXEC);
        if (fd < 0) {
            if (errno == EINTR || errno == ECONNABORTED) continue;
            if (errno == EMFILE || errno == ENFILE || errno == ENOBUFS || errno == ENOMEM) exhausted = true;
            break;  // EAGAIN or a persistent error
        }
        platform::SocketAddress sa;
        const size_t copy = std::min<size_t>(peer_len, sizeof(sa.storage));
        std::memcpy(sa.storage, &peer_addr, copy);
        sa.length = static_cast<uint32_t>(copy);
        platform::SetTcpNoDelay(fd, true).IgnoreError();

        std::shared_ptr<EpollStream> stream;
        try {
            stream = std::make_shared<EpollStream>(this, fd, next_stream_id_.fetch_add(1), sa.ToString(),
                                                   options_.read_buffer_size);
        } catch (...) {
            ::close(fd);
            continue;
        }
        {
            std::lock_guard<std::mutex> lock(streams_mutex_);
            streams_[stream->Id()] = stream;
        }
        if (!stream->Register(epfd_).ok()) {
            stream->Close();
            continue;
        }
        accepted.push_back(std::move(stream));
    }

    if (exhausted) {
        // Descriptor exhaustion: back off briefly instead of spinning on a
        // permanently readable listener.
        std::this_thread::sleep_for(std::chrono::milliseconds(10));
    }
    if (!stopping_.load()) ArmListener(listener);

    for (auto& stream : accepted) {
        if (stopping_.load()) {
            stream->Close();
        } else {
            listener->on_accept(stream);
        }
    }
}

Status EpollService::Post(std::function<void()> fn)
{
    if (!fn) return SG_INVALID_ARGUMENT;
    {
        std::lock_guard<std::mutex> lock(post_mutex_);
        if (!running_.load() || quitting_) return SG_CLOSED;
        tasks_.push_back(std::move(fn));
    }
    const uint64_t one = 1;
    ssize_t n;
    do {
        n = ::write(wake_fd_, &one, sizeof(one));
    } while (n < 0 && errno == EINTR);
    return OkStatus();
}

void EpollService::OnWake()
{
    uint64_t counter = 0;
    ssize_t n;
    do {
        n = ::read(wake_fd_, &counter, sizeof(counter));
    } while (n < 0 && errno == EINTR);

    std::deque<std::function<void()>> batch;
    {
        std::lock_guard<std::mutex> lock(post_mutex_);
        batch.swap(tasks_);
    }
    for (auto& task : batch) {
        try {
            task();
        } catch (...) {
        }
    }
}

void EpollService::WorkerLoop()
{
    epoll_event events[kMaxEvents];
    for (;;) {
        const int n = ::epoll_wait(epfd_, events, kMaxEvents, -1);
        if (n < 0) {
            if (errno == EINTR) continue;
            return;
        }
        for (int i = 0; i < n; ++i) {
            const uint64_t tag = events[i].data.u64;
            if (tag == kWakeTag) {
                OnWake();
                bool quit;
                {
                    std::lock_guard<std::mutex> lock(post_mutex_);
                    quit = quitting_ && tasks_.empty();
                }
                if (quit) {
                    // Chain the wake-up so every other worker also observes the quit.
                    const uint64_t one = 1;
                    ssize_t w;
                    do {
                        w = ::write(wake_fd_, &one, sizeof(one));
                    } while (w < 0 && errno == EINTR);
                    ArmWake();
                    return;
                }
                ArmWake();
            } else if ((tag & kListenerTag) != 0) {
                Listener* listener = nullptr;
                {
                    std::lock_guard<std::mutex> lock(listeners_mutex_);
                    const size_t index = static_cast<size_t>(tag & ~kListenerTag);
                    if (index < listeners_.size()) listener = listeners_[index].get();
                }
                if (listener != nullptr && listener->fd >= 0) OnListenerEvent(listener);
            } else {
                std::shared_ptr<EpollStream> stream;
                {
                    std::lock_guard<std::mutex> lock(streams_mutex_);
                    auto it = streams_.find(tag);
                    if (it != streams_.end()) stream = it->second.lock();
                }
                if (stream) stream->OnEvent(events[i].events);
            }
        }
    }
}

void EpollService::Stop() noexcept
{
    if (!running_.load()) return;
    const std::thread::id self = std::this_thread::get_id();
    for (const auto& w : workers_) {
        if (w.get_id() == self) return;  // contract violation: never stop from a worker
    }
    stopping_ = true;

    {
        std::lock_guard<std::mutex> lock(listeners_mutex_);
        for (auto& l : listeners_) {
            if (l->fd >= 0) {
                ::epoll_ctl(epfd_, EPOLL_CTL_DEL, l->fd, nullptr);
                ::close(l->fd);
                l->fd = -1;
            }
        }
    }

    std::vector<std::shared_ptr<EpollStream>> streams;
    {
        std::lock_guard<std::mutex> lock(streams_mutex_);
        for (auto& entry : streams_) {
            if (auto s = entry.second.lock()) streams.push_back(std::move(s));
        }
    }
    for (auto& s : streams) s->Close();  // failure callbacks are posted to workers
    streams.clear();

    {
        std::lock_guard<std::mutex> lock(post_mutex_);
        quitting_ = true;
    }
    const uint64_t one = 1;
    ssize_t w;
    do {
        w = ::write(wake_fd_, &one, sizeof(one));
    } while (w < 0 && errno == EINTR);

    for (auto& worker : workers_) {
        if (worker.joinable()) worker.join();
    }
    workers_.clear();

    // Run anything that raced the shutdown so no callback is silently dropped.
    std::deque<std::function<void()>> leftovers;
    {
        std::lock_guard<std::mutex> lock(post_mutex_);
        leftovers.swap(tasks_);
    }
    for (auto& task : leftovers) {
        try {
            task();
        } catch (...) {
        }
    }

    {
        std::lock_guard<std::mutex> lock(listeners_mutex_);
        listeners_.clear();
    }
    {
        std::lock_guard<std::mutex> lock(streams_mutex_);
        streams_.clear();
    }
    ::close(wake_fd_);
    ::close(epfd_);
    wake_fd_ = epfd_ = -1;
    {
        std::lock_guard<std::mutex> lock(post_mutex_);
        running_ = false;
        quitting_ = false;
    }
}

}  // namespace

std::unique_ptr<IIoService> CreateIoService() { return std::make_unique<EpollService>(); }

}  // namespace sg::server
