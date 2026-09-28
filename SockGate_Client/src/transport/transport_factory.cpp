#include "transport/transport_factory.h"

#include "transport/tcp_transport.h"

namespace sg::client {

Status CreateConnectedTransport(const TransportRequest& request, std::shared_ptr<net::ITransport>* out,
                                const std::function<void(const std::shared_ptr<net::ITransport>&)>& on_created)
{
    if (out == nullptr) return SG_INVALID_ARGUMENT;
    const uint32_t mode = request.proxy != nullptr ? request.proxy->mode : SG_PROXY_MODE_DIRECT;
    if (mode != SG_PROXY_MODE_DIRECT) return SG_NOT_SUPPORTED;

    TcpTransportOptions options;
    options.connect_timeout_ms = request.connect_timeout_ms;
    options.io_timeout_ms = request.io_timeout_ms;
    auto transport = std::make_shared<TcpTransport>(options);
    if (on_created) on_created(transport);
    SG_TRY(transport->Connect({request.host, request.port}));
    *out = std::move(transport);
    return OkStatus();
}

}  // namespace sg::client
