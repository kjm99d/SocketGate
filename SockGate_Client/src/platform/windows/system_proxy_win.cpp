// System proxy discovery on Windows (only used in SG_PROXY_MODE_SYSTEM).
// The configuration is *read* from WinHTTP's view of the IE settings; the
// connection itself always uses SockGate's own socket transport.
#include "transport/proxy.h"

#include <windows.h>
#include <winhttp.h>

#include <climits>

namespace sg::client {
namespace {

std::string Narrow(const wchar_t* w)
{
    if (w == nullptr) return std::string();
    const int n = WideCharToMultiByte(CP_UTF8, 0, w, -1, nullptr, 0, nullptr, nullptr);
    if (n <= 1) return std::string();
    std::string out(static_cast<size_t>(n - 1), '\0');
    WideCharToMultiByte(CP_UTF8, 0, w, -1, &out[0], n, nullptr, nullptr);
    return out;
}

}  // namespace

Status QuerySystemProxy(const std::string& host, ResolvedProxy* out)
{
    if (out == nullptr) return SG_INVALID_ARGUMENT;
    WINHTTP_CURRENT_USER_IE_PROXY_CONFIG config = {};
    if (!WinHttpGetIEProxyConfigForCurrentUser(&config)) return SG_NOT_FOUND;
    const std::string proxy = Narrow(config.lpszProxy);
    const std::string bypass = Narrow(config.lpszProxyBypass);
    if (config.lpszProxy != nullptr) GlobalFree(config.lpszProxy);
    if (config.lpszProxyBypass != nullptr) GlobalFree(config.lpszProxyBypass);
    if (config.lpszAutoConfigUrl != nullptr) GlobalFree(config.lpszAutoConfigUrl);

    // PAC / WPAD (auto-config) is intentionally unsupported: evaluating
    // JavaScript from the network is out of scope. Only static proxies apply.
    if (proxy.empty()) return SG_NOT_FOUND;
    if (MatchesProxyBypass(host, bypass)) return SG_NOT_FOUND;
    return ParseWindowsProxyList(proxy, out);
}

}  // namespace sg::client
