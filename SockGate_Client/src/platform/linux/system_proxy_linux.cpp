// System proxy discovery on Linux (only used in SG_PROXY_MODE_SYSTEM).
// In DIRECT mode these environment variables are never consulted.
#include "transport/proxy.h"

#include <cstdlib>

namespace sg::client {
namespace {

std::string Env(const char* upper, const char* lower)
{
    const char* v = std::getenv(upper);
    if (v == nullptr || *v == '\0') v = std::getenv(lower);
    return v != nullptr ? std::string(v) : std::string();
}

}  // namespace

Status QuerySystemProxy(const std::string& host, ResolvedProxy* out)
{
    if (out == nullptr) return SG_INVALID_ARGUMENT;
    if (MatchesProxyBypass(host, Env("NO_PROXY", "no_proxy"))) return SG_NOT_FOUND;
    std::string url = Env("ALL_PROXY", "all_proxy");
    if (url.empty()) url = Env("HTTPS_PROXY", "https_proxy");
    if (url.empty()) return SG_NOT_FOUND;
    return ParseProxyUrl(url, out);
}

}  // namespace sg::client
