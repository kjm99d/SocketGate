// Thin, OS-neutral wrapper over BSD-style sockets. Only files under
// platform/<os>/ include OS headers; everything else uses this interface.
#pragma once

#include "sockgate_common/core/status.h"

#include <cstddef>
#include <cstdint>
#include <string>
#include <vector>

namespace sg::platform {

// SOCKET (UINT_PTR) on Windows, int on POSIX. INVALID_SOCKET maps to -1.
using NativeSocket = std::intptr_t;
constexpr NativeSocket kInvalidSocket = -1;

struct SocketAddress {
    alignas(8) uint8_t storage[128] = {};
    uint32_t length = 0;

    int Family() const noexcept;
    uint16_t Port() const noexcept;
    std::string ToString() const;  // "1.2.3.4:443" or "[::1]:443"
};

// Process-wide network stack initialisation (WSAStartup on Windows), reference counted.
class NetworkRuntime {
public:
    NetworkRuntime();
    ~NetworkRuntime();
    NetworkRuntime(const NetworkRuntime&) = delete;
    NetworkRuntime& operator=(const NetworkRuntime&) = delete;

    Status status() const noexcept { return status_; }

private:
    Status status_;
};

// kConnect waits for a non-blocking connect to finish (success or failure).
// kRead/kWrite deliberately ignore exceptional conditions such as TCP urgent
// data, which would otherwise make a wait return immediately forever.
enum class WaitFor { kRead, kWrite, kConnect };

// Resolves host:port. passive=true resolves a bind address ("" = any).
Status ResolveAddresses(const std::string& host, uint16_t port, bool passive,
                        std::vector<SocketAddress>* out);

// Creates a TCP socket that is not inherited by child processes.
Status CreateTcpSocket(int family, bool non_blocking, NativeSocket* out);
void CloseSocket(NativeSocket socket) noexcept;
// Disables both directions; wakes threads blocked waiting on the socket.
void ShutdownSocket(NativeSocket socket) noexcept;

// Begins a non-blocking connect. *in_progress is set when completion must be awaited.
Status StartConnect(NativeSocket socket, const SocketAddress& address, bool* in_progress);
// Retrieves the result of an asynchronous connect (SO_ERROR).
Status FinishConnect(NativeSocket socket);

// Waits until the socket is readable/writable. *ready=false on timeout.
Status WaitSocket(NativeSocket socket, WaitFor what, uint32_t timeout_ms, bool* ready);

// Non-blocking primitives. Return kStatusWouldBlock when no progress is possible,
// SG_CLOSED on orderly EOF (receive), SG_NETWORK_ERROR otherwise.
Status SendSome(NativeSocket socket, const uint8_t* data, size_t size, size_t* sent);
Status ReceiveSome(NativeSocket socket, uint8_t* buffer, size_t capacity, size_t* received);

Status SetTcpNoDelay(NativeSocket socket, bool enable);
Status SetKeepAlive(NativeSocket socket, bool enable);

// Creates, binds and listens. The listening socket is non-inheritable and
// uses exclusive address semantics on Windows.
Status CreateListener(const SocketAddress& address, int backlog, bool non_blocking, NativeSocket* out);
// Blocking accept on a (blocking) listener; the new socket is not
// inheritable. Used by tools and test intermediaries, not by the server
// engine (which uses the asynchronous I/O service).
Status AcceptConnection(NativeSocket listener, NativeSocket* out, SocketAddress* peer);
Status GetLocalAddress(NativeSocket socket, SocketAddress* out);
Status GetPeerAddress(NativeSocket socket, SocketAddress* out);

// Last socket error code of the calling thread (WSAGetLastError / errno), for logging only.
int LastSocketError() noexcept;

}  // namespace sg::platform
