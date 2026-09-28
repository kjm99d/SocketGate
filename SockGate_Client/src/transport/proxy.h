// Proxy support: tunnel negotiation over an already connected transport and
// proxy configuration parsing.
//
// Security note: the proxy only ever sees TLS ciphertext. Server identity is
// established end-to-end by certificate validation / SPKI pinning / server
// proof, and client authentication is bound to the end-to-end TLS channel,
// so a proxy (or anything behind it) cannot forge or relay a session.
// Proxy responses are nevertheless parsed as hostile input.
#pragma once

#include "session/client_session.h"

#include "sockgate_common/core/clock.h"
#include "sockgate_common/net/transport.h"

#include <string>
#include <vector>

namespace sg::client {

// HTTP/1.1 CONNECT (optional Basic credentials). Reads the response header
// byte by byte (max 8 KiB) so no tunnelled bytes are consumed.
Status NegotiateHttpConnect(net::ITransport& transport, const std::string& host, uint16_t port,
                            const std::string& username, ByteView password, const Deadline& deadline);

// SOCKS4a (hostname resolved by the proxy). `user_id` is optional.
Status NegotiateSocks4a(net::ITransport& transport, const std::string& host, uint16_t port, const std::string& user_id,
                        const Deadline& deadline);

// SOCKS5 with hostname address type; no-auth or username/password (RFC 1929).
Status NegotiateSocks5(net::ITransport& transport, const std::string& host, uint16_t port,
                       const std::string& username, ByteView password, const Deadline& deadline);

// A proxy resolved from configuration.
struct ResolvedProxy {
    uint32_t type = 0;  // SG_PROXY_TYPE_*
    std::string host;
    uint16_t port = 0;
    std::string username;
    SecureBytes password;
};

// Parses "scheme://[user[:password]@]host[:port]" with schemes http,
// socks4a, socks5, socks5h. A bare "host:port" is treated as http.
Status ParseProxyUrl(const std::string& url, ResolvedProxy* out);

// Parses a WinINet/WinHTTP proxy list ("host:port" or
// "http=h:p;https=h:p;socks=h:p") and picks the entry for HTTPS traffic.
Status ParseWindowsProxyList(const std::string& list, ResolvedProxy* out);

// True if `host` matches a no_proxy / bypass list (comma or semicolon
// separated; entries may be "*", exact names, ".suffix", "*.suffix" or
// "<local>" for dot-less names).
bool MatchesProxyBypass(const std::string& host, const std::string& bypass_list);

// Reads the operating system's proxy configuration for `host`.
// SG_NOT_FOUND when no proxy applies (connect directly).
// Windows: WinHTTP IE settings (static proxy only; PAC/WPAD unsupported).
// Linux:   ALL_PROXY / all_proxy, then HTTPS_PROXY / https_proxy, honouring NO_PROXY / no_proxy.
Status QuerySystemProxy(const std::string& host, ResolvedProxy* out);

}  // namespace sg::client
