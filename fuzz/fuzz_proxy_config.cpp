// Fuzz target: proxy configuration parsers (URLs from the environment,
// WinINet/WinHTTP proxy lists, no_proxy / bypass lists). Byte 0 selects the
// parser; accepted configurations must be well formed.
#include "fuzz_target.h"

#include "transport/proxy.h"

#include <sockgate/config.h>

#include <cstdlib>
#include <string>

using namespace sg;
using namespace sg::client;

namespace {

void Check(bool condition)
{
    if (!condition) std::abort();
}

void CheckResolved(const ResolvedProxy& p)
{
    Check(!p.host.empty());
    Check(p.port != 0);
    Check(p.type == SG_PROXY_TYPE_HTTP_CONNECT || p.type == SG_PROXY_TYPE_SOCKS4A || p.type == SG_PROXY_TYPE_SOCKS5);
    Check(p.host.find('\0') == std::string::npos);
}

}  // namespace

extern "C" int LLVMFuzzerTestOneInput(const uint8_t* data, size_t size)
{
    if (size < 1) return 0;
    const std::string text(reinterpret_cast<const char*>(data + 1), size - 1);
    ResolvedProxy proxy;
    switch (data[0] % 3) {
    case 0:
        if (ParseProxyUrl(text, &proxy).ok()) CheckResolved(proxy);
        break;
    case 1:
        if (ParseWindowsProxyList(text, &proxy).ok()) CheckResolved(proxy);
        break;
    default: {
        const size_t split = text.find('\n');
        const std::string host = text.substr(0, split);
        const std::string list = split == std::string::npos ? std::string() : text.substr(split + 1);
        (void)MatchesProxyBypass(host, list);
        // An empty list never matches; "*" always does.
        Check(!MatchesProxyBypass(host, ""));
        if (!host.empty()) Check(MatchesProxyBypass(host, "*"));
        break;
    }
    }
    return 0;
}

std::vector<std::vector<uint8_t>> SockGateFuzzSeeds()
{
    std::vector<std::vector<uint8_t>> seeds;
    auto add = [&](uint8_t selector, const std::string& s) {
        std::vector<uint8_t> v = {selector};
        v.insert(v.end(), s.begin(), s.end());
        seeds.push_back(v);
    };
    add(0, "http://proxy.example.com:8080");
    add(0, "socks5h://user:p%40ss@10.0.0.1:1080");
    add(0, "socks4a://[::1]:1080");
    add(0, "proxy:3128");
    add(1, "proxy.corp:8080");
    add(1, "http=h1:80;https=h2:443;socks=h3:1080");
    add(1, "socks=127.0.0.1:9050");
    add(2, "api.example.com\n.example.com,localhost");
    add(2, "intranet\n<local>;*.corp");
    add(2, "10.1.2.3\n10.1.2.3");
    return seeds;
}
