#include "transport/tcp_transport.h"

#include "sockgate_common/core/clock.h"

#include <vector>

namespace sg::client {
namespace {

// Upper bound for a single wait so a missed wake-up is noticed quickly.
constexpr uint32_t kWaitSliceMs = 200;

}  // namespace

// Registers an operation as in flight so Close() does not release the socket
// underneath it. Fails with SG_CLOSED once Shutdown() has been requested.
class TcpTransport::InFlight {
public:
    explicit InFlight(TcpTransport* owner) : owner_(owner)
    {
        std::lock_guard<std::mutex> lock(owner_->mutex_);
        if (owner_->shutdown_ || owner_->socket_ == platform::kInvalidSocket) {
            status_ = SG_CLOSED;
            return;
        }
        socket_ = owner_->socket_;
        ++owner_->in_flight_;
    }

    ~InFlight()
    {
        if (!status_.ok()) return;
        std::lock_guard<std::mutex> lock(owner_->mutex_);
        if (--owner_->in_flight_ == 0) owner_->idle_cv_.notify_all();
    }

    Status status() const { return status_; }
    platform::NativeSocket socket() const { return socket_; }
    bool ShutdownRequested() const
    {
        std::lock_guard<std::mutex> lock(owner_->mutex_);
        return owner_->shutdown_;
    }

private:
    TcpTransport* owner_;
    Status status_ = OkStatus();
    platform::NativeSocket socket_ = platform::kInvalidSocket;
};

TcpTransport::TcpTransport(const TcpTransportOptions& options) : options_(options) {}

TcpTransport::~TcpTransport() { Close(); }

Status TcpTransport::Connect(const net::Endpoint& endpoint)
{
    SG_TRY(runtime_.status());
    if (endpoint.host.empty() || endpoint.port == 0) return SG_INVALID_ARGUMENT;
    {
        std::lock_guard<std::mutex> lock(mutex_);
        if (shutdown_) return SG_CLOSED;
        if (connected_ || socket_ != platform::kInvalidSocket) return SG_INVALID_STATE;
    }

    std::vector<platform::SocketAddress> addresses;
    SG_TRY(platform::ResolveAddresses(endpoint.host, endpoint.port, false, &addresses));

    const Deadline deadline(options_.connect_timeout_ms);
    Status last = SG_NETWORK_ERROR;
    for (const auto& address : addresses) {
        if (deadline.Expired()) return SG_TIMEOUT;
        // 0 means "no timeout", so a finite budget is never allowed to round down to 0.
        const uint32_t remaining = deadline.RemainingMs(UINT32_MAX);
        const uint32_t budget = deadline.infinite() ? 0 : (remaining == 0 ? 1 : remaining);
        last = ConnectOne(address, budget);
        if (last.ok() || last == SG_CLOSED) return last;  // SG_CLOSED: shutdown requested
    }
    return last;
}

Status TcpTransport::ConnectOne(const platform::SocketAddress& address, uint32_t timeout_ms)
{
    platform::NativeSocket s = platform::kInvalidSocket;
    SG_TRY(platform::CreateTcpSocket(address.Family(), true, &s));
    {
        // Publish the socket first so Shutdown() can interrupt the connect.
        std::lock_guard<std::mutex> lock(mutex_);
        if (shutdown_) {
            platform::CloseSocket(s);
            return SG_CLOSED;
        }
        socket_ = s;
    }

    Status result = OkStatus();
    {
        InFlight op(this);
        result = op.status();
        bool in_progress = false;
        if (result.ok()) result = platform::StartConnect(s, address, &in_progress);
        const Deadline deadline(timeout_ms);
        while (result.ok() && in_progress) {
            if (op.ShutdownRequested()) {
                result = SG_CLOSED;
                break;
            }
            if (deadline.Expired()) {
                result = SG_TIMEOUT;
                break;
            }
            bool ready = false;
            result = platform::WaitSocket(s, platform::WaitFor::kConnect, deadline.RemainingMs(kWaitSliceMs), &ready);
            if (result.ok() && ready) {
                if (op.ShutdownRequested()) {
                    result = SG_CLOSED;
                    break;
                }
                result = platform::FinishConnect(s);
                in_progress = false;
            }
        }
        if (result.ok()) {
            // Still inside the in-flight scope: Close() cannot release s meanwhile.
            platform::SetTcpNoDelay(s, true).IgnoreError();
            platform::SetKeepAlive(s, true).IgnoreError();
        }
    }

    std::lock_guard<std::mutex> lock(mutex_);
    if (result.ok()) {
        // Close() may have raced the end of the connect and already released s.
        if (shutdown_ || socket_ != s) return SG_CLOSED;
        peer_ = address.ToString();
        connected_ = true;
        return OkStatus();
    }
    // Failed attempt: release the socket only if we still own it. Close() may
    // already have closed it, and the handle number may since have been reused.
    if (socket_ == s) {
        socket_ = platform::kInvalidSocket;
        platform::CloseSocket(s);
    }
    return result;
}

Status TcpTransport::Send(const uint8_t* data, size_t size)
{
    return SendFor(data, size, options_.io_timeout_ms);
}

Status TcpTransport::SendFor(const uint8_t* data, size_t size, uint32_t timeout_ms)
{
    if (data == nullptr && size != 0) return SG_INVALID_ARGUMENT;
    // Registered as in flight *before* waiting for the serial lock, so Close()
    // (and the destructor) wait until this thread has released send_mutex_.
    InFlight op(this);
    SG_TRY(op.status());
    std::lock_guard<std::mutex> serial(send_mutex_);

    const Deadline deadline(timeout_ms);
    size_t offset = 0;
    while (offset < size) {
        if (op.ShutdownRequested()) return SG_CLOSED;
        size_t sent = 0;
        const Status st = platform::SendSome(op.socket(), data + offset, size - offset, &sent);
        if (st.ok()) {
            offset += sent;
            continue;
        }
        if (st != kStatusWouldBlock) return op.ShutdownRequested() ? Status(SG_CLOSED) : st;
        if (deadline.Expired()) return SG_TIMEOUT;
        bool ready = false;
        SG_TRY(platform::WaitSocket(op.socket(), platform::WaitFor::kWrite, deadline.RemainingMs(kWaitSliceMs), &ready));
    }
    return OkStatus();
}

Status TcpTransport::Receive(uint8_t* buffer, size_t capacity, size_t* received)
{
    return ReceiveFor(buffer, capacity, received, options_.io_timeout_ms);
}

Status TcpTransport::ReceiveFor(uint8_t* buffer, size_t capacity, size_t* received, uint32_t timeout_ms)
{
    if (buffer == nullptr || capacity == 0 || received == nullptr) return SG_INVALID_ARGUMENT;
    *received = 0;
    InFlight op(this);  // before the serial lock, see Send()
    SG_TRY(op.status());
    std::lock_guard<std::mutex> serial(receive_mutex_);

    const Deadline deadline(timeout_ms);
    for (;;) {
        if (op.ShutdownRequested()) return SG_CLOSED;
        const Status st = platform::ReceiveSome(op.socket(), buffer, capacity, received);
        if (st.ok()) return OkStatus();
        if (st != kStatusWouldBlock) return op.ShutdownRequested() ? Status(SG_CLOSED) : st;
        if (deadline.Expired()) return SG_TIMEOUT;
        bool ready = false;
        SG_TRY(platform::WaitSocket(op.socket(), platform::WaitFor::kRead, deadline.RemainingMs(kWaitSliceMs), &ready));
    }
}

void TcpTransport::Shutdown() noexcept
{
    std::lock_guard<std::mutex> lock(mutex_);
    if (shutdown_) return;
    shutdown_ = true;
    // Wakes any thread blocked in select/poll on this socket.
    if (socket_ != platform::kInvalidSocket) platform::ShutdownSocket(socket_);
}

void TcpTransport::Close() noexcept
{
    Shutdown();
    std::unique_lock<std::mutex> lock(mutex_);
    idle_cv_.wait(lock, [this]() { return in_flight_ == 0; });
    if (socket_ != platform::kInvalidSocket) {
        platform::CloseSocket(socket_);
        socket_ = platform::kInvalidSocket;
    }
    connected_ = false;
}

std::string TcpTransport::PeerAddress() const
{
    std::lock_guard<std::mutex> lock(mutex_);
    return peer_;
}

}  // namespace sg::client
