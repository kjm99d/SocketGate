// Winsock2 implementation of sockgate_common/platform/socket.h.
#include "sockgate_common/platform/socket.h"

#include <winsock2.h>
#include <ws2tcpip.h>
#include <windows.h>

#include <climits>
#include <cstring>
#include <mutex>

namespace sg::platform {
namespace {

std::mutex g_runtime_mutex;
unsigned g_runtime_refs = 0;

SOCKET ToSocket(NativeSocket s) noexcept { return static_cast<SOCKET>(s); }

bool Utf8ToWide(const std::string& in, std::wstring* out)
{
    out->clear();
    if (in.empty()) return true;
    if (in.size() > static_cast<size_t>(INT_MAX)) return false;
    const int n = MultiByteToWideChar(CP_UTF8, MB_ERR_INVALID_CHARS, in.data(), static_cast<int>(in.size()), nullptr, 0);
    if (n <= 0) return false;
    out->resize(static_cast<size_t>(n));
    return MultiByteToWideChar(CP_UTF8, MB_ERR_INVALID_CHARS, in.data(), static_cast<int>(in.size()),
                               out->data(), n) == n;
}

bool IsWouldBlock(int err) noexcept { return err == WSAEWOULDBLOCK || err == WSAEINPROGRESS; }

}  // namespace

int SocketAddress::Family() const noexcept
{
    if (length < sizeof(sockaddr)) return AF_UNSPEC;
    sockaddr sa;
    std::memcpy(&sa, storage, sizeof(sa));
    return sa.sa_family;
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

NetworkRuntime::NetworkRuntime()
{
    std::lock_guard<std::mutex> lock(g_runtime_mutex);
    if (g_runtime_refs == 0) {
        WSADATA data;
        if (WSAStartup(MAKEWORD(2, 2), &data) != 0) {
            status_ = SG_NETWORK_ERROR;
            return;
        }
    }
    ++g_runtime_refs;
}

NetworkRuntime::~NetworkRuntime()
{
    if (!status_.ok()) return;
    std::lock_guard<std::mutex> lock(g_runtime_mutex);
    if (g_runtime_refs > 0 && --g_runtime_refs == 0) WSACleanup();
}

Status ResolveAddresses(const std::string& host, uint16_t port, bool passive, std::vector<SocketAddress>* out)
{
    if (out == nullptr) return SG_INVALID_ARGUMENT;
    out->clear();

    std::wstring whost;
    if (!Utf8ToWide(host, &whost)) return SG_INVALID_ARGUMENT;
    const std::wstring wport = std::to_wstring(port);

    ADDRINFOW hints = {};
    hints.ai_family = AF_UNSPEC;
    hints.ai_socktype = SOCK_STREAM;
    hints.ai_protocol = IPPROTO_TCP;
    hints.ai_flags = passive ? AI_PASSIVE : AI_ADDRCONFIG;

    ADDRINFOW* result = nullptr;
    const int rc = GetAddrInfoW(whost.empty() ? nullptr : whost.c_str(), wport.c_str(), &hints, &result);
    if (rc != 0 || result == nullptr) return SG_NETWORK_ERROR;

    for (ADDRINFOW* ai = result; ai != nullptr; ai = ai->ai_next) {
        if (ai->ai_addr == nullptr || ai->ai_addrlen == 0 || ai->ai_addrlen > sizeof(SocketAddress::storage)) continue;
        if (ai->ai_family != AF_INET && ai->ai_family != AF_INET6) continue;
        SocketAddress addr;
        std::memcpy(addr.storage, ai->ai_addr, ai->ai_addrlen);
        addr.length = static_cast<uint32_t>(ai->ai_addrlen);
        out->push_back(addr);
    }
    FreeAddrInfoW(result);
    return out->empty() ? Status(SG_NETWORK_ERROR) : OkStatus();
}

Status CreateTcpSocket(int family, bool non_blocking, NativeSocket* out)
{
    if (out == nullptr) return SG_INVALID_ARGUMENT;
    *out = kInvalidSocket;
    SOCKET s = WSASocketW(family, SOCK_STREAM, IPPROTO_TCP, nullptr, 0,
                          WSA_FLAG_OVERLAPPED | WSA_FLAG_NO_HANDLE_INHERIT);
    if (s == INVALID_SOCKET) return SG_NETWORK_ERROR;
    if (non_blocking) {
        u_long mode = 1;
        if (ioctlsocket(s, FIONBIO, &mode) != 0) {
            closesocket(s);
            return SG_NETWORK_ERROR;
        }
    }
    *out = static_cast<NativeSocket>(s);
    return OkStatus();
}

void CloseSocket(NativeSocket socket) noexcept
{
    if (socket != kInvalidSocket) closesocket(ToSocket(socket));
}

void ShutdownSocket(NativeSocket socket) noexcept
{
    if (socket != kInvalidSocket) shutdown(ToSocket(socket), SD_BOTH);
}

Status StartConnect(NativeSocket socket, const SocketAddress& address, bool* in_progress)
{
    if (in_progress == nullptr || address.length == 0) return SG_INVALID_ARGUMENT;
    *in_progress = false;
    if (connect(ToSocket(socket), reinterpret_cast<const sockaddr*>(address.storage),
                static_cast<int>(address.length)) == 0) {
        return OkStatus();
    }
    if (IsWouldBlock(WSAGetLastError())) {
        *in_progress = true;
        return OkStatus();
    }
    return SG_NETWORK_ERROR;
}

Status FinishConnect(NativeSocket socket)
{
    int error = 0;
    int len = sizeof(error);
    if (getsockopt(ToSocket(socket), SOL_SOCKET, SO_ERROR, reinterpret_cast<char*>(&error), &len) != 0) {
        return SG_NETWORK_ERROR;
    }
    return error == 0 ? OkStatus() : Status(SG_NETWORK_ERROR);
}

Status WaitSocket(NativeSocket socket, WaitFor what, uint32_t timeout_ms, bool* ready)
{
    if (ready == nullptr) return SG_INVALID_ARGUMENT;
    *ready = false;
    // select() is used instead of WSAPoll: it reliably reports failed
    // non-blocking connects through the exception set on all Windows 10 builds.
    // The exception set is only consulted for connects: for reads/writes it
    // would also signal out-of-band data and make every wait return at once.
    fd_set primary;
    fd_set except;
    FD_ZERO(&primary);
    FD_ZERO(&except);
    FD_SET(ToSocket(socket), &primary);
    timeval tv;
    tv.tv_sec = static_cast<long>(timeout_ms / 1000);
    tv.tv_usec = static_cast<long>((timeout_ms % 1000) * 1000);
    int rc;
    switch (what) {
    case WaitFor::kRead:
        rc = select(0, &primary, nullptr, nullptr, &tv);
        break;
    case WaitFor::kWrite:
        rc = select(0, nullptr, &primary, nullptr, &tv);
        break;
    case WaitFor::kConnect:
    default:
        FD_SET(ToSocket(socket), &except);
        rc = select(0, nullptr, &primary, &except, &tv);
        break;
    }
    if (rc == SOCKET_ERROR) return SG_NETWORK_ERROR;
    // A failed connect (exception set) also counts as "ready": the following
    // FinishConnect() reports the actual error.
    *ready = rc > 0;
    return OkStatus();
}

Status SendSome(NativeSocket socket, const uint8_t* data, size_t size, size_t* sent)
{
    if (sent == nullptr || (data == nullptr && size != 0)) return SG_INVALID_ARGUMENT;
    *sent = 0;
    if (size == 0) return OkStatus();
    const int chunk = size > static_cast<size_t>(INT_MAX) ? INT_MAX : static_cast<int>(size);
    const int n = send(ToSocket(socket), reinterpret_cast<const char*>(data), chunk, 0);
    if (n == SOCKET_ERROR) {
        return IsWouldBlock(WSAGetLastError()) ? Status(kStatusWouldBlock) : Status(SG_NETWORK_ERROR);
    }
    *sent = static_cast<size_t>(n);
    return OkStatus();
}

Status ReceiveSome(NativeSocket socket, uint8_t* buffer, size_t capacity, size_t* received)
{
    if (received == nullptr || buffer == nullptr || capacity == 0) return SG_INVALID_ARGUMENT;
    *received = 0;
    const int chunk = capacity > static_cast<size_t>(INT_MAX) ? INT_MAX : static_cast<int>(capacity);
    const int n = recv(ToSocket(socket), reinterpret_cast<char*>(buffer), chunk, 0);
    if (n == SOCKET_ERROR) {
        const int err = WSAGetLastError();
        if (IsWouldBlock(err)) return kStatusWouldBlock;
        if (err == WSAESHUTDOWN) return SG_CLOSED;
        return SG_NETWORK_ERROR;
    }
    if (n == 0) return SG_CLOSED;
    *received = static_cast<size_t>(n);
    return OkStatus();
}

Status SetTcpNoDelay(NativeSocket socket, bool enable)
{
    const BOOL value = enable ? TRUE : FALSE;
    return setsockopt(ToSocket(socket), IPPROTO_TCP, TCP_NODELAY, reinterpret_cast<const char*>(&value),
                      sizeof(value)) == 0
               ? OkStatus()
               : Status(SG_NETWORK_ERROR);
}

Status SetKeepAlive(NativeSocket socket, bool enable)
{
    const BOOL value = enable ? TRUE : FALSE;
    return setsockopt(ToSocket(socket), SOL_SOCKET, SO_KEEPALIVE, reinterpret_cast<const char*>(&value),
                      sizeof(value)) == 0
               ? OkStatus()
               : Status(SG_NETWORK_ERROR);
}

Status CreateListener(const SocketAddress& address, int backlog, bool non_blocking, NativeSocket* out)
{
    if (out == nullptr || address.length == 0) return SG_INVALID_ARGUMENT;
    NativeSocket s = kInvalidSocket;
    SG_TRY(CreateTcpSocket(address.Family(), non_blocking, &s));

    // Prevent other processes from hijacking the port (SO_REUSEADDR semantics on Windows are unsafe).
    const BOOL exclusive = TRUE;
    if (setsockopt(ToSocket(s), SOL_SOCKET, SO_EXCLUSIVEADDRUSE, reinterpret_cast<const char*>(&exclusive),
                   sizeof(exclusive)) != 0 ||
        bind(ToSocket(s), reinterpret_cast<const sockaddr*>(address.storage), static_cast<int>(address.length)) != 0 ||
        listen(ToSocket(s), backlog > 0 ? backlog : SOMAXCONN) != 0) {
        CloseSocket(s);
        return SG_NETWORK_ERROR;
    }
    *out = s;
    return OkStatus();
}

Status GetLocalAddress(NativeSocket socket, SocketAddress* out)
{
    if (out == nullptr) return SG_INVALID_ARGUMENT;
    int len = static_cast<int>(sizeof(out->storage));
    if (getsockname(ToSocket(socket), reinterpret_cast<sockaddr*>(out->storage), &len) != 0) return SG_NETWORK_ERROR;
    out->length = static_cast<uint32_t>(len);
    return OkStatus();
}

Status GetPeerAddress(NativeSocket socket, SocketAddress* out)
{
    if (out == nullptr) return SG_INVALID_ARGUMENT;
    int len = static_cast<int>(sizeof(out->storage));
    if (getpeername(ToSocket(socket), reinterpret_cast<sockaddr*>(out->storage), &len) != 0) return SG_NETWORK_ERROR;
    out->length = static_cast<uint32_t>(len);
    return OkStatus();
}

int LastSocketError() noexcept { return WSAGetLastError(); }

}  // namespace sg::platform
