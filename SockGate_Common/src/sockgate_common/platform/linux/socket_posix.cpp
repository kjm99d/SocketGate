// POSIX (Linux) implementation of sockgate_common/platform/socket.h.
#include "sockgate_common/platform/socket.h"

#include <arpa/inet.h>
#include <cerrno>
#include <cstring>
#include <fcntl.h>
#include <netdb.h>
#include <netinet/in.h>
#include <netinet/tcp.h>
#include <poll.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <unistd.h>

namespace sg::platform {
namespace {

int ToFd(NativeSocket s) noexcept { return static_cast<int>(s); }

bool IsWouldBlock(int err) noexcept { return err == EAGAIN || err == EWOULDBLOCK || err == EINPROGRESS; }

}  // namespace

int SocketAddress::Family() const noexcept
{
    if (length < sizeof(sa_family_t)) return AF_UNSPEC;
    sockaddr_storage ss;
    std::memcpy(&ss, storage, sizeof(storage) < sizeof(ss) ? sizeof(storage) : sizeof(ss));
    return ss.ss_family;
}

uint16_t SocketAddress::Port() const noexcept
{
    if (Family() == AF_INET && length >= sizeof(sockaddr_in)) {
        sockaddr_in in;
        std::memcpy(&in, storage, sizeof(in));
        return ntohs(in.sin_port);
    }
    if (Family() == AF_INET6 && length >= sizeof(sockaddr_in6)) {
        sockaddr_in6 in6;
        std::memcpy(&in6, storage, sizeof(in6));
        return ntohs(in6.sin6_port);
    }
    return 0;
}

std::string SocketAddress::ToString() const
{
    char host[INET6_ADDRSTRLEN] = {};
    if (Family() == AF_INET && length >= sizeof(sockaddr_in)) {
        sockaddr_in in;
        std::memcpy(&in, storage, sizeof(in));
        if (inet_ntop(AF_INET, &in.sin_addr, host, sizeof(host)) == nullptr) return "?";
        return std::string(host) + ":" + std::to_string(ntohs(in.sin_port));
    }
    if (Family() == AF_INET6 && length >= sizeof(sockaddr_in6)) {
        sockaddr_in6 in6;
        std::memcpy(&in6, storage, sizeof(in6));
        if (inet_ntop(AF_INET6, &in6.sin6_addr, host, sizeof(host)) == nullptr) return "?";
        return "[" + std::string(host) + "]:" + std::to_string(ntohs(in6.sin6_port));
    }
    return "?";
}

NetworkRuntime::NetworkRuntime() = default;
NetworkRuntime::~NetworkRuntime() = default;

Status ResolveAddresses(const std::string& host, uint16_t port, bool passive, std::vector<SocketAddress>* out)
{
    if (out == nullptr) return SG_INVALID_ARGUMENT;
    out->clear();
    if (host.find('\0') != std::string::npos) return SG_INVALID_ARGUMENT;

    addrinfo hints;
    std::memset(&hints, 0, sizeof(hints));
    hints.ai_family = AF_UNSPEC;
    hints.ai_socktype = SOCK_STREAM;
    hints.ai_protocol = IPPROTO_TCP;
    hints.ai_flags = passive ? AI_PASSIVE : AI_ADDRCONFIG;

    const std::string service = std::to_string(port);
    addrinfo* result = nullptr;
    const int rc = getaddrinfo(host.empty() ? nullptr : host.c_str(), service.c_str(), &hints, &result);
    if (rc != 0 || result == nullptr) return SG_NETWORK_ERROR;

    for (addrinfo* ai = result; ai != nullptr; ai = ai->ai_next) {
        if (ai->ai_addr == nullptr || ai->ai_addrlen == 0 || ai->ai_addrlen > sizeof(SocketAddress::storage)) continue;
        if (ai->ai_family != AF_INET && ai->ai_family != AF_INET6) continue;
        SocketAddress addr;
        std::memcpy(addr.storage, ai->ai_addr, ai->ai_addrlen);
        addr.length = static_cast<uint32_t>(ai->ai_addrlen);
        out->push_back(addr);
    }
    freeaddrinfo(result);
    return out->empty() ? Status(SG_NETWORK_ERROR) : OkStatus();
}

Status CreateTcpSocket(int family, bool non_blocking, NativeSocket* out)
{
    if (out == nullptr) return SG_INVALID_ARGUMENT;
    *out = kInvalidSocket;
    const int type = SOCK_STREAM | SOCK_CLOEXEC | (non_blocking ? SOCK_NONBLOCK : 0);
    const int fd = ::socket(family, type, IPPROTO_TCP);
    if (fd < 0) return SG_NETWORK_ERROR;
    *out = fd;
    return OkStatus();
}

void CloseSocket(NativeSocket socket) noexcept
{
    if (socket != kInvalidSocket) ::close(ToFd(socket));
}

void ShutdownSocket(NativeSocket socket) noexcept
{
    if (socket != kInvalidSocket) ::shutdown(ToFd(socket), SHUT_RDWR);
}

Status StartConnect(NativeSocket socket, const SocketAddress& address, bool* in_progress)
{
    if (in_progress == nullptr || address.length == 0) return SG_INVALID_ARGUMENT;
    *in_progress = false;
    int rc;
    do {
        rc = ::connect(ToFd(socket), reinterpret_cast<const sockaddr*>(address.storage),
                       static_cast<socklen_t>(address.length));
    } while (rc != 0 && errno == EINTR);
    if (rc == 0) return OkStatus();
    if (IsWouldBlock(errno)) {
        *in_progress = true;
        return OkStatus();
    }
    return SG_NETWORK_ERROR;
}

Status FinishConnect(NativeSocket socket)
{
    int error = 0;
    socklen_t len = sizeof(error);
    if (::getsockopt(ToFd(socket), SOL_SOCKET, SO_ERROR, &error, &len) != 0) return SG_NETWORK_ERROR;
    return error == 0 ? OkStatus() : Status(SG_NETWORK_ERROR);
}

Status WaitSocket(NativeSocket socket, WaitFor what, uint32_t timeout_ms, bool* ready)
{
    if (ready == nullptr) return SG_INVALID_ARGUMENT;
    *ready = false;
    pollfd pfd;
    pfd.fd = ToFd(socket);
    pfd.events = static_cast<short>(what == WaitFor::kRead ? POLLIN : POLLOUT);
    pfd.revents = 0;
    const int timeout = timeout_ms > 0x7FFFFFFFu ? 0x7FFFFFFF : static_cast<int>(timeout_ms);
    const int rc = ::poll(&pfd, 1, timeout);
    if (rc < 0) {
        if (errno == EINTR) return OkStatus();  // treated as a spurious wake-up
        return SG_NETWORK_ERROR;
    }
    // POLLERR/POLLHUP also count as ready: the following operation reports the error.
    *ready = rc > 0;
    return OkStatus();
}

Status SendSome(NativeSocket socket, const uint8_t* data, size_t size, size_t* sent)
{
    if (sent == nullptr || (data == nullptr && size != 0)) return SG_INVALID_ARGUMENT;
    *sent = 0;
    if (size == 0) return OkStatus();
    ssize_t n;
    do {
        n = ::send(ToFd(socket), data, size, MSG_NOSIGNAL);
    } while (n < 0 && errno == EINTR);
    if (n < 0) return IsWouldBlock(errno) ? Status(kStatusWouldBlock) : Status(SG_NETWORK_ERROR);
    *sent = static_cast<size_t>(n);
    return OkStatus();
}

Status ReceiveSome(NativeSocket socket, uint8_t* buffer, size_t capacity, size_t* received)
{
    if (received == nullptr || buffer == nullptr || capacity == 0) return SG_INVALID_ARGUMENT;
    *received = 0;
    ssize_t n;
    do {
        n = ::recv(ToFd(socket), buffer, capacity, 0);
    } while (n < 0 && errno == EINTR);
    if (n < 0) return IsWouldBlock(errno) ? Status(kStatusWouldBlock) : Status(SG_NETWORK_ERROR);
    if (n == 0) return SG_CLOSED;
    *received = static_cast<size_t>(n);
    return OkStatus();
}

Status SetTcpNoDelay(NativeSocket socket, bool enable)
{
    const int value = enable ? 1 : 0;
    return ::setsockopt(ToFd(socket), IPPROTO_TCP, TCP_NODELAY, &value, sizeof(value)) == 0
               ? OkStatus()
               : Status(SG_NETWORK_ERROR);
}

Status SetKeepAlive(NativeSocket socket, bool enable)
{
    const int value = enable ? 1 : 0;
    return ::setsockopt(ToFd(socket), SOL_SOCKET, SO_KEEPALIVE, &value, sizeof(value)) == 0
               ? OkStatus()
               : Status(SG_NETWORK_ERROR);
}

Status CreateListener(const SocketAddress& address, int backlog, bool non_blocking, NativeSocket* out)
{
    if (out == nullptr || address.length == 0) return SG_INVALID_ARGUMENT;
    NativeSocket s = kInvalidSocket;
    SG_TRY(CreateTcpSocket(address.Family(), non_blocking, &s));

    // SO_REUSEADDR on Linux only allows rebinding over TIME_WAIT; it does not
    // permit a second listener on the same port (unlike Windows semantics).
    const int reuse = 1;
    if (::setsockopt(ToFd(s), SOL_SOCKET, SO_REUSEADDR, &reuse, sizeof(reuse)) != 0 ||
        ::bind(ToFd(s), reinterpret_cast<const sockaddr*>(address.storage),
               static_cast<socklen_t>(address.length)) != 0 ||
        ::listen(ToFd(s), backlog > 0 ? backlog : SOMAXCONN) != 0) {
        CloseSocket(s);
        return SG_NETWORK_ERROR;
    }
    *out = s;
    return OkStatus();
}

Status GetLocalAddress(NativeSocket socket, SocketAddress* out)
{
    if (out == nullptr) return SG_INVALID_ARGUMENT;
    socklen_t len = sizeof(out->storage);
    if (::getsockname(ToFd(socket), reinterpret_cast<sockaddr*>(out->storage), &len) != 0) return SG_NETWORK_ERROR;
    out->length = static_cast<uint32_t>(len);
    return OkStatus();
}

Status GetPeerAddress(NativeSocket socket, SocketAddress* out)
{
    if (out == nullptr) return SG_INVALID_ARGUMENT;
    socklen_t len = sizeof(out->storage);
    if (::getpeername(ToFd(socket), reinterpret_cast<sockaddr*>(out->storage), &len) != 0) return SG_NETWORK_ERROR;
    out->length = static_cast<uint32_t>(len);
    return OkStatus();
}

int LastSocketError() noexcept { return errno; }

}  // namespace sg::platform
