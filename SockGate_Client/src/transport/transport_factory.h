// Creates the connected byte transport for a client connection according to
// the proxy policy: direct TCP (default), explicitly configured proxy, or the
// system proxy configuration (only when explicitly requested).
//
// SockGate never picks up proxy settings implicitly: WinHTTP/WinINet
// settings and http_proxy/https_proxy/ALL_PROXY are ignored in DIRECT mode.
#pragma once

#include "session/client_session.h"

#include "sockgate_common/core/log.h"
#include "sockgate_common/net/transport.h"

#include <functional>
#include <memory>
#include <string>

namespace sg::client {

struct TransportRequest {
    std::string host;
    uint16_t port = 0;
    uint32_t connect_timeout_ms = 10'000;
    uint32_t io_timeout_ms = 30'000;
    const ProxySettings* proxy = nullptr;  // nullptr = direct
    const Logger* logger = nullptr;
};

// `on_created` is invoked with the transport before any blocking connect so
// the caller can abort it from another thread (Shutdown()).
Status CreateConnectedTransport(const TransportRequest& request, std::shared_ptr<net::ITransport>* out,
                                const std::function<void(const std::shared_ptr<net::ITransport>&)>& on_created);

}  // namespace sg::client
