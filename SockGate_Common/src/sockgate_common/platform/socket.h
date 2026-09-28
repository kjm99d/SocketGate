#pragma once
/**
 * @file
 * @brief Thin, OS-neutral wrapper over BSD-style sockets.
 *
 * Only files under `platform/<os>/` include OS headers; everything else uses this interface. Implemented in
 * platform/windows/socket_win.cpp (Winsock2) and platform/linux/socket_posix.cpp (POSIX).
 *
 * @note The functions keep no shared state (except NetworkRuntime's reference count) and may be called from any
 *       thread; synchronising use of one socket is the caller's responsibility.
 */

#include "sockgate_common/core/status.h"

#include <cstddef>
#include <cstdint>
#include <string>
#include <vector>

namespace sg::platform {

/** @brief Native socket handle: SOCKET (UINT_PTR) on Windows, int on POSIX. INVALID_SOCKET maps to -1. */
using NativeSocket = std::intptr_t;
/** @brief The invalid socket handle (INVALID_SOCKET on Windows, -1 on POSIX). */
constexpr NativeSocket kInvalidSocket = -1;

/** @brief Socket address (IPv4 or IPv6) stored as raw OS sockaddr bytes. */
struct SocketAddress {
    alignas(8) uint8_t storage[128] = {};  ///< OS sockaddr (sockaddr_in / sockaddr_in6).
    uint32_t length = 0;                   ///< Valid bytes in storage; 0 = no address.

    /**
     * @brief Returns the address family.
     * @return AF_INET, AF_INET6 or another AF_* value; AF_UNSPEC when @ref length is too short to hold one.
     */
    int Family() const noexcept;
    /**
     * @brief Returns the port in host byte order.
     * @return The port for IPv4/IPv6 addresses; 0 otherwise.
     */
    uint16_t Port() const noexcept;
    /**
     * @brief Formats the address and port.
     * @return "1.2.3.4:443" or "[::1]:443"; "?" for other families or on failure.
     */
    std::string ToString() const;
};

/**
 * @brief Process-wide network stack initialisation (WSAStartup on Windows), reference counted.
 *
 * On Windows, the first instance calls WSAStartup and the last one to be destroyed calls WSACleanup, so an
 * instance must be alive while the functions in this header are used; on POSIX the class does nothing.
 *
 * @note Construction and destruction are thread-safe (the count is protected by a mutex). Not copyable.
 */
class NetworkRuntime {
public:
    /** @brief Takes a reference on the network stack, initialising it if this is the first one. */
    NetworkRuntime();
    /** @brief Releases the reference taken by a successful construction. */
    ~NetworkRuntime();
    NetworkRuntime(const NetworkRuntime&) = delete;
    NetworkRuntime& operator=(const NetworkRuntime&) = delete;

    /**
     * @brief Returns the initialisation result.
     * @retval SG_OK            The network stack is usable.
     * @retval SG_NETWORK_ERROR WSAStartup failed (Windows).
     */
    Status status() const noexcept { return status_; }

private:
    Status status_;  ///< Initialisation result.
};

/**
 * @brief Readiness condition for WaitSocket().
 *
 * kConnect waits for a non-blocking connect to finish (success or failure). kRead/kWrite deliberately ignore
 * exceptional conditions such as TCP urgent data, which would otherwise make a wait return immediately forever.
 */
enum class WaitFor { kRead, /**< Readable. */ kWrite, /**< Writable. */ kConnect /**< Connect finished. */ };

/**
 * @brief Resolves host:port to IPv4/IPv6 TCP addresses.
 *
 * passive=true resolves a bind address ("" = any). Results of other address families are skipped.
 *
 * @param[in]  host    DNS name or IP literal (UTF-8); "" for none.
 * @param[in]  port    TCP port.
 * @param[in]  passive true to resolve a bind address (AI_PASSIVE); false for a connect address (AI_ADDRCONFIG).
 * @param[out] out     Resolved addresses (cleared first).
 * @retval SG_OK               At least one address was resolved.
 * @retval SG_INVALID_ARGUMENT @p out is null, or @p host is not valid UTF-8 (Windows) or contains a NUL (POSIX).
 * @retval SG_NETWORK_ERROR    Resolution failed or produced no IPv4/IPv6 address.
 */
Status ResolveAddresses(const std::string& host, uint16_t port, bool passive,
                        std::vector<SocketAddress>* out);

/**
 * @brief Creates a TCP socket that is not inherited by child processes.
 *
 * Windows sockets are created for overlapped I/O.
 *
 * @param[in]  family       Address family (AF_INET or AF_INET6).
 * @param[in]  non_blocking true to put the socket in non-blocking mode.
 * @param[out] out          The new socket; set to kInvalidSocket on failure.
 * @retval SG_OK               Success.
 * @retval SG_INVALID_ARGUMENT @p out is null.
 * @retval SG_NETWORK_ERROR    The socket could not be created or configured.
 */
Status CreateTcpSocket(int family, bool non_blocking, NativeSocket* out);
/**
 * @brief Closes a socket; does nothing for kInvalidSocket.
 * @param[in] socket Socket to close.
 */
void CloseSocket(NativeSocket socket) noexcept;
/**
 * @brief Disables both directions; wakes threads blocked waiting on the socket.
 *
 * Does nothing for kInvalidSocket. The handle stays open; release it with CloseSocket().
 *
 * @param[in] socket Socket to shut down.
 */
void ShutdownSocket(NativeSocket socket) noexcept;

/**
 * @brief Begins a non-blocking connect. *in_progress is set when completion must be awaited.
 *
 * When @p in_progress is set, wait with WaitSocket(WaitFor::kConnect) and then call FinishConnect().
 *
 * @param[in]  socket      Non-blocking socket.
 * @param[in]  address     Remote address.
 * @param[out] in_progress true when the connect is pending; false when it completed immediately.
 * @retval SG_OK               Connected, or the connect is in progress.
 * @retval SG_INVALID_ARGUMENT @p in_progress is null or @p address is empty.
 * @retval SG_NETWORK_ERROR    The connect failed.
 */
Status StartConnect(NativeSocket socket, const SocketAddress& address, bool* in_progress);
/**
 * @brief Retrieves the result of an asynchronous connect (SO_ERROR).
 * @param[in] socket Socket passed to StartConnect().
 * @retval SG_OK            The connect succeeded.
 * @retval SG_NETWORK_ERROR The connect failed or its result could not be read.
 */
Status FinishConnect(NativeSocket socket);

/**
 * @brief Waits until the socket is readable/writable. *ready=false on timeout.
 *
 * An error, hang-up or failed connect also counts as ready: the following operation (or FinishConnect())
 * reports the actual error. On POSIX an interrupted wait (EINTR) returns SG_OK with *ready=false.
 *
 * @param[in]  socket     Socket to wait on.
 * @param[in]  what       Condition to wait for.
 * @param[in]  timeout_ms Maximum wait in milliseconds (0 = do not wait).
 * @param[out] ready      true when the condition is signalled.
 * @retval SG_OK               The wait completed (check @p ready).
 * @retval SG_INVALID_ARGUMENT @p ready is null.
 * @retval SG_NETWORK_ERROR    The wait failed.
 */
Status WaitSocket(NativeSocket socket, WaitFor what, uint32_t timeout_ms, bool* ready);

/**
 * @brief Non-blocking send of up to @p size bytes; may send fewer.
 *
 * Non-blocking primitives return kStatusWouldBlock when no progress is possible, SG_CLOSED on orderly EOF
 * (receive), SG_NETWORK_ERROR otherwise. On POSIX no SIGPIPE is raised.
 *
 * @param[in]  socket Socket.
 * @param[in]  data   Bytes to send; may be null only when @p size is 0.
 * @param[in]  size   Number of bytes (0 sends nothing and succeeds).
 * @param[out] sent   Number of bytes sent.
 * @retval SG_OK               @p sent bytes were sent.
 * @retval kStatusWouldBlock   No progress is possible now.
 * @retval SG_INVALID_ARGUMENT @p sent is null, or @p data is null with a non-zero @p size.
 * @retval SG_NETWORK_ERROR    Any other failure.
 */
Status SendSome(NativeSocket socket, const uint8_t* data, size_t size, size_t* sent);
/**
 * @brief Non-blocking receive of up to @p capacity bytes.
 * @param[in]  socket   Socket.
 * @param[out] buffer   Destination.
 * @param[in]  capacity Size of @p buffer; must not be 0.
 * @param[out] received Number of bytes received.
 * @retval SG_OK               At least one byte was received.
 * @retval kStatusWouldBlock   No data is available now.
 * @retval SG_CLOSED           Orderly EOF (on Windows also a socket that was shut down).
 * @retval SG_INVALID_ARGUMENT @p received or @p buffer is null, or @p capacity is 0.
 * @retval SG_NETWORK_ERROR    Any other failure.
 */
Status ReceiveSome(NativeSocket socket, uint8_t* buffer, size_t capacity, size_t* received);

/**
 * @brief Enables or disables TCP_NODELAY (Nagle's algorithm off when enabled).
 * @param[in] socket Socket.
 * @param[in] enable true to set TCP_NODELAY.
 * @retval SG_OK            Success.
 * @retval SG_NETWORK_ERROR The option could not be set.
 */
Status SetTcpNoDelay(NativeSocket socket, bool enable);
/**
 * @brief Enables or disables SO_KEEPALIVE.
 * @param[in] socket Socket.
 * @param[in] enable true to set SO_KEEPALIVE.
 * @retval SG_OK            Success.
 * @retval SG_NETWORK_ERROR The option could not be set.
 */
Status SetKeepAlive(NativeSocket socket, bool enable);

/**
 * @brief Creates, binds and listens.
 *
 * The listening socket is non-inheritable and uses exclusive address semantics on Windows (SO_EXCLUSIVEADDRUSE,
 * so no other process can take over the port). On Linux SO_REUSEADDR is set, which only allows rebinding over
 * TIME_WAIT.
 *
 * @param[in]  address      Local address to bind.
 * @param[in]  backlog      Listen backlog; 0 or less selects SOMAXCONN.
 * @param[in]  non_blocking true to make the listening socket non-blocking.
 * @param[out] out          The listening socket.
 * @retval SG_OK               Success.
 * @retval SG_INVALID_ARGUMENT @p out is null or @p address is empty.
 * @retval SG_NETWORK_ERROR    Creating, binding or listening failed (the socket is closed again).
 */
Status CreateListener(const SocketAddress& address, int backlog, bool non_blocking, NativeSocket* out);
/**
 * @brief Blocking accept on a (blocking) listener; the new socket is not inheritable.
 *
 * Used by tools and test intermediaries, not by the server engine (which uses the asynchronous I/O service).
 *
 * @param[in]  listener Listening socket.
 * @param[out] out      The accepted socket.
 * @param[out] peer     Receives the peer address; may be null.
 * @retval SG_OK               A connection was accepted.
 * @retval SG_INVALID_ARGUMENT @p out is null.
 * @retval SG_NETWORK_ERROR    accept failed.
 */
Status AcceptConnection(NativeSocket listener, NativeSocket* out, SocketAddress* peer);
/**
 * @brief Returns the local address of a socket (getsockname).
 * @param[in]  socket Socket.
 * @param[out] out    Local address.
 * @retval SG_OK               Success.
 * @retval SG_INVALID_ARGUMENT @p out is null.
 * @retval SG_NETWORK_ERROR    The address could not be read.
 */
Status GetLocalAddress(NativeSocket socket, SocketAddress* out);
/**
 * @brief Returns the remote address of a connected socket (getpeername).
 * @param[in]  socket Socket.
 * @param[out] out    Peer address.
 * @retval SG_OK               Success.
 * @retval SG_INVALID_ARGUMENT @p out is null.
 * @retval SG_NETWORK_ERROR    The address could not be read.
 */
Status GetPeerAddress(NativeSocket socket, SocketAddress* out);

/**
 * @brief Last socket error code of the calling thread (WSAGetLastError / errno), for logging only.
 * @return The OS error code.
 */
int LastSocketError() noexcept;

}  // namespace sg::platform
