#pragma once
/**
 * @file
 * @brief Creates the connected byte transport for a client connection according to the proxy policy.
 *
 * Direct TCP (default), explicitly configured proxy, or the system proxy configuration (only when explicitly
 * requested).
 *
 * SockGate never picks up proxy settings implicitly: WinHTTP/WinINet settings and http_proxy/https_proxy/ALL_PROXY
 * are ignored in DIRECT mode.
 */

#include "session/client_session.h"

#include "sockgate_common/core/log.h"
#include "sockgate_common/net/transport.h"

#include <functional>
#include <memory>
#include <string>

namespace sg::client {

/** @brief Parameters of CreateConnectedTransport(). */
struct TransportRequest {
    std::string host;  ///< Server host; resolved locally when direct, by the proxy otherwise.
    uint16_t port = 0;  ///< Server port.
    /**
     * @brief Budget for the system proxy lookup, name resolution, TCP connect and proxy negotiation (ms); 0 = none.
     *
     * It is checked between steps: a single system proxy lookup or resolver call cannot be interrupted, and proxy
     * requests are written with io_timeout_ms (the budget bounds reading the proxy's answers).
     */
    uint32_t connect_timeout_ms = 10'000;
    uint32_t io_timeout_ms = 30'000;  ///< I/O timeout of the created transport (ms); 0 = no timeout.
    const ProxySettings* proxy = nullptr;  ///< Proxy policy (not owned); nullptr = direct.
    const Logger* logger = nullptr;  ///< Optional logger for proxy events (not owned); credentials are never logged.
};

/**
 * @brief Creates a TcpTransport and connects it to the server, directly or through a proxy tunnel.
 *
 * DIRECT connects to the server. EXPLICIT uses the configured proxy. SYSTEM asks QuerySystemProxy() and connects
 * directly when no proxy applies. With a proxy, the TCP connection goes to the proxy and the tunnel to the server
 * is negotiated (HTTP CONNECT, SOCKS4a or SOCKS5); the result carries only the server's byte stream.
 *
 * `on_created` is invoked with the transport before any blocking connect so the caller can abort it from another
 * thread (Shutdown()).
 *
 * @param[in]  request    Target, budget and proxy policy.
 * @param[out] out        Receives the connected transport (with a proxy: the open tunnel).
 * @param[in]  on_created Optional; called at most once, after the system proxy lookup and before the TCP connect.
 * @retval SG_OK               Connected.
 * @retval SG_INVALID_ARGUMENT @p out is nullptr, unknown proxy mode or type, or a target or credential the proxy
 *                             protocol cannot carry.
 * @retval SG_TIMEOUT          The budget ran out.
 * @retval SG_CLOSED           The transport was shut down during the TCP connect.
 * @retval SG_PROXY_ERROR      The proxy could not be reached or refused the tunnel, or the system proxy
 *                             configuration could not be used.
 * @retval SG_NOT_SUPPORTED    The system proxy uses an unsupported scheme.
 * @return Otherwise the TcpTransport::Connect() error of a direct connection.
 */
Status CreateConnectedTransport(const TransportRequest& request, std::shared_ptr<net::ITransport>* out,
                                const std::function<void(const std::shared_ptr<net::ITransport>&)>& on_created);

}  // namespace sg::client
