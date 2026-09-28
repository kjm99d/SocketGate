#include "transport/transport_factory.h"

#include "transport/proxy.h"
#include "transport/tcp_transport.h"

#include <sockgate/config.h>

#include <algorithm>

namespace sg::client {
namespace {

const char* ProxyTypeName(uint32_t type)
{
    switch (type) {
    case SG_PROXY_TYPE_HTTP_CONNECT: return "http-connect";
    case SG_PROXY_TYPE_SOCKS4A: return "socks4a";
    case SG_PROXY_TYPE_SOCKS5: return "socks5";
    default: return "unknown";
    }
}

}  // namespace

Status CreateConnectedTransport(const TransportRequest& request, std::shared_ptr<net::ITransport>* out,
                                const std::function<void(const std::shared_ptr<net::ITransport>&)>& on_created)
{
    if (out == nullptr) return SG_INVALID_ARGUMENT;
    const uint32_t mode = request.proxy != nullptr ? request.proxy->mode : SG_PROXY_MODE_DIRECT;
    // The connect timeout covers the system proxy lookup, name resolution, the
    // TCP connect and the proxy negotiation.
    const Deadline deadline(request.connect_timeout_ms);

    // Resolve which proxy (if any) applies. DIRECT never consults the system.
    bool use_proxy = false;
    ResolvedProxy proxy;
    if (mode == SG_PROXY_MODE_EXPLICIT) {
        use_proxy = true;
        proxy.type = request.proxy->type;
        proxy.host = request.proxy->host;
        proxy.port = request.proxy->port;
        proxy.username = request.proxy->username;
        proxy.password = request.proxy->password;
    } else if (mode == SG_PROXY_MODE_SYSTEM) {
        const Status st = QuerySystemProxy(request.host, &proxy);
        if (st.ok()) {
            use_proxy = true;
        } else if (st != SG_NOT_FOUND) {
            return st == SG_NOT_SUPPORTED ? Status(SG_NOT_SUPPORTED) : Status(SG_PROXY_ERROR);
        }
    } else if (mode != SG_PROXY_MODE_DIRECT) {
        return SG_INVALID_ARGUMENT;
    }

    if (deadline.Expired()) return SG_TIMEOUT;
    TcpTransportOptions options;
    options.connect_timeout_ms = deadline.infinite() ? 0u : std::max<uint32_t>(1, deadline.RemainingMs(UINT32_MAX));
    // Session I/O timeout; proxy negotiation reads are bounded separately by
    // `deadline` (the connect timeout).
    options.io_timeout_ms = request.io_timeout_ms;
    auto transport = std::make_shared<TcpTransport>(options);
    if (on_created) on_created(transport);

    if (!use_proxy) {
        SG_TRY(transport->Connect({request.host, request.port}));
        *out = std::move(transport);
        return OkStatus();
    }

    const Status connected = transport->Connect({proxy.host, proxy.port});
    if (!connected.ok()) {
        if (request.logger != nullptr) {
            SG_LOGW(*request.logger, "event=proxy_connect_failed proxy=%s:%u type=%s err=%s", proxy.host.c_str(),
                    static_cast<unsigned>(proxy.port), ProxyTypeName(proxy.type), connected.name());
        }
        return connected == SG_TIMEOUT || connected == SG_CLOSED ? connected : Status(SG_PROXY_ERROR);
    }
    Status st;
    switch (proxy.type) {
    case SG_PROXY_TYPE_HTTP_CONNECT:
        st = NegotiateHttpConnect(*transport, request.host, request.port, proxy.username, proxy.password, deadline);
        break;
    case SG_PROXY_TYPE_SOCKS4A:
        st = NegotiateSocks4a(*transport, request.host, request.port, proxy.username, deadline);
        break;
    case SG_PROXY_TYPE_SOCKS5:
        st = NegotiateSocks5(*transport, request.host, request.port, proxy.username, proxy.password, deadline);
        break;
    default:
        st = SG_INVALID_ARGUMENT;
        break;
    }
    if (!st.ok()) {
        if (request.logger != nullptr) {
            SG_LOGW(*request.logger, "event=proxy_negotiation_failed proxy=%s:%u type=%s err=%s", proxy.host.c_str(),
                    static_cast<unsigned>(proxy.port), ProxyTypeName(proxy.type), st.name());
        }
        transport->Close();
        return st;
    }
    if (request.logger != nullptr) {
        // Credentials are never logged.
        SG_LOGI(*request.logger, "event=proxy_tunnel_established proxy=%s:%u type=%s", proxy.host.c_str(),
                static_cast<unsigned>(proxy.port), ProxyTypeName(proxy.type));
    }
    *out = std::move(transport);
    return OkStatus();
}

}  // namespace sg::client
