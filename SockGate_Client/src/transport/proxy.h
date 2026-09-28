#pragma once
/**
 * @file
 * @brief Proxy support: tunnel negotiation over an already connected transport and proxy configuration parsing.
 *
 * Security note: the proxy only ever sees TLS ciphertext. Server identity is established end-to-end by certificate
 * validation / SPKI pinning / server proof, and client authentication is bound to the end-to-end TLS channel, so a
 * proxy (or anything behind it) cannot forge or relay a session. Proxy responses are nevertheless parsed as hostile
 * input.
 *
 * @warning The connection to the proxy itself is plain TCP: proxy credentials (HTTP Basic, SOCKS5 RFC 1929) travel
 *          unencrypted to the proxy.
 *
 * The target host of every Negotiate*() function must consist of 1..255 letters, digits, '.', '-', ':' or '_'
 * (host names and IP literals only), so it cannot inject protocol syntax. In all of them @p deadline bounds the
 * reads of the proxy's answer; requests are written with the transport's I/O timeout.
 */

#include "session/client_session.h"

#include "sockgate_common/core/clock.h"
#include "sockgate_common/net/transport.h"

#include <string>
#include <vector>

namespace sg::client {

/**
 * @brief Opens a tunnel with HTTP/1.1 CONNECT.
 *
 * HTTP/1.1 CONNECT (optional Basic credentials). Reads the response header byte by byte (max 8 KiB) so no
 * tunnelled bytes are consumed.
 *
 * Basic credentials are sent only when @p username is not empty. After sending, the final request buffer and the
 * encoded-credentials string are zeroed, but temporary strings and reallocated buffers built on the way are not
 * wiped. Any 2xx status succeeds.
 *
 * @param[in] transport Transport connected to the proxy.
 * @param[in] host      Target host (IPv6 literals without brackets).
 * @param[in] port      Target port.
 * @param[in] username  Basic user name; "" = no credentials. No control characters, at most 255 bytes.
 * @param[in] password  Basic password (used only with a user name).
 * @param[in] deadline  Bound for reading the response.
 * @retval SG_OK               Tunnel open.
 * @retval SG_INVALID_ARGUMENT Invalid host, port 0, or invalid user name.
 * @retval SG_PROXY_ERROR      Write or read failure, non-2xx status (e.g. 407, 403, 502), malformed or oversized
 *                             response header.
 * @retval SG_TIMEOUT          @p deadline passed.
 */
Status NegotiateHttpConnect(net::ITransport& transport, const std::string& host, uint16_t port,
                            const std::string& username, ByteView password, const Deadline& deadline);

/**
 * @brief Opens a tunnel with SOCKS4a.
 *
 * SOCKS4a (hostname resolved by the proxy). `user_id` is optional. Succeeds only when the proxy grants the request
 * (reply code 0x5A).
 *
 * @param[in] transport Transport connected to the proxy.
 * @param[in] host      Target host.
 * @param[in] port      Target port.
 * @param[in] user_id   SOCKS user id; "" = none. At most 255 bytes, no NUL.
 * @param[in] deadline  Bound for reading the reply.
 * @retval SG_OK               Tunnel open.
 * @retval SG_INVALID_ARGUMENT Invalid host, port 0, or invalid user id.
 * @retval SG_PROXY_ERROR      Write or read failure, or the request was not granted.
 * @retval SG_TIMEOUT          @p deadline passed.
 */
Status NegotiateSocks4a(net::ITransport& transport, const std::string& host, uint16_t port, const std::string& user_id,
                        const Deadline& deadline);

/**
 * @brief Opens a tunnel with SOCKS5.
 *
 * SOCKS5 with hostname address type; no-auth or username/password (RFC 1929). Exactly one method is offered
 * (username/password when @p username is not empty, else no-auth) and only that method is accepted. The bound
 * address of the reply is consumed so no reply bytes leak into the TLS stream.
 *
 * @param[in] transport Transport connected to the proxy.
 * @param[in] host      Target host (sent as a domain name, resolved by the proxy).
 * @param[in] port      Target port.
 * @param[in] username  User name; "" = no authentication. At most 255 bytes.
 * @param[in] password  Password (used only with a user name). At most 255 bytes.
 * @param[in] deadline  Bound for reading the replies.
 * @retval SG_OK               Tunnel open.
 * @retval SG_INVALID_ARGUMENT Invalid host, port 0, or credentials longer than 255 bytes.
 * @retval SG_PROXY_ERROR      Write or read failure, rejected method or credentials, failed CONNECT, or a
 *                             malformed reply.
 * @retval SG_TIMEOUT          @p deadline passed.
 */
Status NegotiateSocks5(net::ITransport& transport, const std::string& host, uint16_t port,
                       const std::string& username, ByteView password, const Deadline& deadline);

/** @brief A proxy resolved from configuration. */
struct ResolvedProxy {
    uint32_t type = 0;  ///< SG_PROXY_TYPE_*.
    std::string host;   ///< Proxy host name or IP literal (IPv6 without brackets).
    uint16_t port = 0;  ///< Proxy port.
    std::string username;  ///< User name (SOCKS4a: user id); "" = none.
    SecureBytes password;  ///< Password; wiped on release.
};

/**
 * @brief Parses a proxy URL.
 *
 * Parses "scheme://[user[:password]@]host[:port]" with schemes http, socks4a, socks5, socks5h. A bare "host:port"
 * is treated as http.
 *
 * The scheme is case-insensitive; "socks4" is accepted as SOCKS4a and socks5h is the same as socks5 (the host name
 * is always resolved by the proxy). Default ports: 8080 (http), 1080 (SOCKS). Anything after the first '/' is
 * ignored; user information is used as written (no percent-decoding); IPv6 hosts are given in brackets. @p out may
 * be partly written on failure.
 *
 * @param[in]  url Proxy URL; surrounding white space is ignored.
 * @param[out] out Receives the proxy.
 * @retval SG_OK               Parsed.
 * @retval SG_INVALID_ARGUMENT @p out is nullptr; empty, longer than 1024 characters or containing control
 *                             characters; invalid host or port; user name or password longer than 255 bytes.
 * @retval SG_NOT_SUPPORTED    Any other scheme (e.g. https:// proxies, i.e. TLS to the proxy).
 */
Status ParseProxyUrl(const std::string& url, ResolvedProxy* out);

/**
 * @brief Parses a Windows proxy list.
 *
 * Parses a WinINet/WinHTTP proxy list ("host:port" or "http=h:p;https=h:p;socks=h:p") and picks the entry for
 * HTTPS traffic.
 *
 * Without '=', the first entry (entries are separated by ';' or spaces) applies to every protocol. Otherwise the
 * https= entry is preferred, then socks= (SOCKS4a, as in WinINet), then http=. Entries are parsed with
 * ParseProxyUrl(), whose errors are passed through.
 *
 * @param[in]  list Proxy list.
 * @param[out] out  Receives the proxy.
 * @retval SG_OK               Parsed.
 * @retval SG_NOT_FOUND        Empty list, or none of the entries above.
 * @retval SG_INVALID_ARGUMENT @p out is nullptr.
 */
Status ParseWindowsProxyList(const std::string& list, ResolvedProxy* out);

/**
 * @brief Checks a host against a proxy bypass list.
 *
 * True if `host` matches a no_proxy / bypass list (comma or semicolon separated; entries may be "*", exact names,
 * ".suffix", "*.suffix" or "<local>" for dot-less names).
 *
 * Spaces also separate entries, and matching ignores case. ".suffix" and "*.suffix" also match the bare domain,
 * and a plain name also matches its subdomains (curl-style: "example.com" matches "a.example.com"). Ports and
 * address ranges are not interpreted.
 *
 * @param[in] host        Target host.
 * @param[in] bypass_list Bypass list.
 * @return True when @p host is to be reached without a proxy.
 */
bool MatchesProxyBypass(const std::string& host, const std::string& bypass_list);

/**
 * @brief Reads the operating system's proxy configuration for `host`.
 *
 * SG_NOT_FOUND when no proxy applies (connect directly).
 * - Windows: WinHTTP IE settings (static proxy only; PAC/WPAD unsupported). The bypass list is applied; settings
 *   that cannot be read count as "no proxy". The proxy list is parsed with ParseWindowsProxyList().
 * - Linux: ALL_PROXY / all_proxy, then HTTPS_PROXY / https_proxy, honouring NO_PROXY / no_proxy. The upper-case
 *   variable wins unless it is unset or empty; the URL is parsed with ParseProxyUrl().
 *
 * Only used in SG_PROXY_MODE_SYSTEM; DIRECT mode never consults these settings.
 *
 * @param[in]  host Target host.
 * @param[out] out  Receives the proxy.
 * @retval SG_OK               A proxy applies.
 * @retval SG_NOT_FOUND        No proxy applies.
 * @retval SG_INVALID_ARGUMENT @p out is nullptr, or the configured proxy cannot be parsed.
 * @retval SG_NOT_SUPPORTED    The configured proxy uses an unsupported scheme.
 */
Status QuerySystemProxy(const std::string& host, ResolvedProxy* out);

}  // namespace sg::client
