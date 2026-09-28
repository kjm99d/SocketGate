#include "transport/proxy.h"

#include "sockgate_common/serialization/base64.h"

#include <sockgate/config.h>

#include <algorithm>
#include <cctype>
#include <cstring>

namespace sg::client {
namespace {

constexpr size_t kMaxHttpHeader = 8 * 1024;
constexpr size_t kMaxProxyField = 255;

uint32_t Remaining(const Deadline& deadline)
{
    if (deadline.infinite()) return net::kNoTimeout;
    return std::max<uint32_t>(1, deadline.RemainingMs(UINT32_MAX));
}

Status ReadExactly(net::ITransport& t, uint8_t* out, size_t size, const Deadline& deadline)
{
    size_t got = 0;
    while (got < size) {
        if (deadline.Expired()) return SG_TIMEOUT;
        size_t n = 0;
        const Status st = t.ReceiveFor(out + got, size - got, &n, Remaining(deadline));
        if (st == SG_TIMEOUT) return st;
        if (!st.ok()) return SG_PROXY_ERROR;
        got += n;
    }
    return OkStatus();
}

bool IsValidHostForProxy(const std::string& host)
{
    if (host.empty() || host.size() > kMaxProxyField) return false;
    for (char c : host) {
        // Hostnames / IP literals only: nothing that could inject protocol syntax.
        const bool ok = std::isalnum(static_cast<unsigned char>(c)) || c == '.' || c == '-' || c == ':' || c == '_';
        if (!ok) return false;
    }
    return true;
}

bool HasControlOrSeparator(const std::string& s)
{
    for (char c : s) {
        const auto u = static_cast<unsigned char>(c);
        if (u < 0x20 || u == 0x7F) return true;
    }
    return false;
}

std::string ToLower(std::string s)
{
    std::transform(s.begin(), s.end(), s.begin(), [](char c) { return static_cast<char>(std::tolower(static_cast<unsigned char>(c))); });
    return s;
}

std::string Trim(const std::string& s)
{
    size_t b = 0;
    size_t e = s.size();
    while (b < e && std::isspace(static_cast<unsigned char>(s[b]))) ++b;
    while (e > b && std::isspace(static_cast<unsigned char>(s[e - 1]))) --e;
    return s.substr(b, e - b);
}

Status ParseHostPort(const std::string& text, uint16_t default_port, std::string* host, uint16_t* port)
{
    std::string h = text;
    std::string p;
    if (!h.empty() && h[0] == '[') {  // [ipv6]:port
        const size_t close = h.find(']');
        if (close == std::string::npos) return SG_INVALID_ARGUMENT;
        if (close + 1 < h.size()) {
            if (h[close + 1] != ':') return SG_INVALID_ARGUMENT;
            p = h.substr(close + 2);
        }
        h = h.substr(1, close - 1);
    } else {
        const size_t colon = h.rfind(':');
        if (colon != std::string::npos && h.find(':') == colon) {
            p = h.substr(colon + 1);
            h = h.substr(0, colon);
        }
    }
    if (!IsValidHostForProxy(h)) return SG_INVALID_ARGUMENT;
    uint32_t value = default_port;
    if (!p.empty()) {
        if (p.size() > 5) return SG_INVALID_ARGUMENT;
        value = 0;
        for (char c : p) {
            if (c < '0' || c > '9') return SG_INVALID_ARGUMENT;
            value = value * 10 + static_cast<uint32_t>(c - '0');
        }
    }
    if (value == 0 || value > 65535) return SG_INVALID_ARGUMENT;
    *host = h;
    *port = static_cast<uint16_t>(value);
    return OkStatus();
}

}  // namespace

// ---- HTTP CONNECT ---------------------------------------------------------------------

Status NegotiateHttpConnect(net::ITransport& transport, const std::string& host, uint16_t port,
                            const std::string& username, ByteView password, const Deadline& deadline)
{
    if (!IsValidHostForProxy(host) || port == 0 || HasControlOrSeparator(username) || username.size() > kMaxProxyField) {
        return SG_INVALID_ARGUMENT;
    }
    const bool ipv6 = host.find(':') != std::string::npos;
    const std::string authority = (ipv6 ? "[" + host + "]" : host) + ":" + std::to_string(port);
    std::string request = "CONNECT " + authority + " HTTP/1.1\r\nHost: " + authority + "\r\n";
    if (!username.empty()) {
        SecureBytes credentials(username.begin(), username.end());
        credentials.push_back(':');
        credentials.insert(credentials.end(), password.begin(), password.end());
        std::string encoded;
        // Standard base64 (RFC 7617) derived from the url-safe variant.
        encoded = ser::Base64UrlEncode(ByteView(credentials));
        for (char& c : encoded) {
            if (c == '-') c = '+';
            if (c == '_') c = '/';
        }
        while (encoded.size() % 4 != 0) encoded.push_back('=');
        request += "Proxy-Authorization: Basic " + encoded + "\r\n";
        SecureZero(&encoded[0], encoded.size());
    }
    request += "\r\n";
    const Status sent = transport.Send(reinterpret_cast<const uint8_t*>(request.data()), request.size());
    SecureZero(&request[0], request.size());
    if (!sent.ok()) return SG_PROXY_ERROR;

    // Read the response header one byte at a time up to CRLFCRLF.
    std::string header;
    while (header.size() < 4 || header.compare(header.size() - 4, 4, "\r\n\r\n") != 0) {
        if (header.size() >= kMaxHttpHeader) return SG_PROXY_ERROR;
        uint8_t b = 0;
        SG_TRY(ReadExactly(transport, &b, 1, deadline));
        header.push_back(static_cast<char>(b));
    }
    // Status line: "HTTP/1.x SSS reason"
    const size_t eol = header.find("\r\n");
    const std::string status_line = header.substr(0, eol);
    if (status_line.size() < 12 || status_line.compare(0, 7, "HTTP/1.") != 0 || status_line[8] != ' ') {
        return SG_PROXY_ERROR;
    }
    const std::string code = status_line.substr(9, 3);
    if (code.size() != 3 || !std::all_of(code.begin(), code.end(), [](char c) { return c >= '0' && c <= '9'; })) {
        return SG_PROXY_ERROR;
    }
    if (code[0] != '2') return SG_PROXY_ERROR;  // 407 (auth), 403, 502 ...
    return OkStatus();
}

// ---- SOCKS4a ----------------------------------------------------------------------------

Status NegotiateSocks4a(net::ITransport& transport, const std::string& host, uint16_t port, const std::string& user_id,
                        const Deadline& deadline)
{
    if (!IsValidHostForProxy(host) || port == 0 || user_id.size() > kMaxProxyField ||
        user_id.find('\0') != std::string::npos) {
        return SG_INVALID_ARGUMENT;
    }
    Bytes req = {0x04, 0x01, static_cast<uint8_t>(port >> 8), static_cast<uint8_t>(port), 0x00, 0x00, 0x00, 0x01};
    req.insert(req.end(), user_id.begin(), user_id.end());
    req.push_back(0x00);
    req.insert(req.end(), host.begin(), host.end());
    req.push_back(0x00);
    if (!transport.Send(req.data(), req.size()).ok()) return SG_PROXY_ERROR;

    uint8_t reply[8];
    SG_TRY(ReadExactly(transport, reply, sizeof(reply), deadline));
    if (reply[0] != 0x00 || reply[1] != 0x5A) return SG_PROXY_ERROR;  // 0x5A = request granted
    return OkStatus();
}

// ---- SOCKS5 -----------------------------------------------------------------------------

Status NegotiateSocks5(net::ITransport& transport, const std::string& host, uint16_t port,
                       const std::string& username, ByteView password, const Deadline& deadline)
{
    if (!IsValidHostForProxy(host) || port == 0 || username.size() > kMaxProxyField ||
        password.size() > kMaxProxyField) {
        return SG_INVALID_ARGUMENT;
    }
    const bool with_auth = !username.empty();
    const Bytes greeting = with_auth ? Bytes{0x05, 0x01, 0x02} : Bytes{0x05, 0x01, 0x00};
    if (!transport.Send(greeting.data(), greeting.size()).ok()) return SG_PROXY_ERROR;
    uint8_t choice[2];
    SG_TRY(ReadExactly(transport, choice, sizeof(choice), deadline));
    if (choice[0] != 0x05) return SG_PROXY_ERROR;
    // Only accept exactly the method we offered (0xFF = none acceptable).
    if (choice[1] != (with_auth ? 0x02 : 0x00)) return SG_PROXY_ERROR;

    if (with_auth) {
        SecureBytes auth = {0x01, static_cast<uint8_t>(username.size())};
        auth.insert(auth.end(), username.begin(), username.end());
        auth.push_back(static_cast<uint8_t>(password.size()));
        auth.insert(auth.end(), password.begin(), password.end());
        if (!transport.Send(auth.data(), auth.size()).ok()) return SG_PROXY_ERROR;
        uint8_t status[2];
        SG_TRY(ReadExactly(transport, status, sizeof(status), deadline));
        if (status[0] != 0x01 || status[1] != 0x00) return SG_PROXY_ERROR;
    }

    Bytes req = {0x05, 0x01, 0x00, 0x03, static_cast<uint8_t>(host.size())};  // CONNECT, domain name
    req.insert(req.end(), host.begin(), host.end());
    req.push_back(static_cast<uint8_t>(port >> 8));
    req.push_back(static_cast<uint8_t>(port));
    if (!transport.Send(req.data(), req.size()).ok()) return SG_PROXY_ERROR;

    uint8_t head[4];
    SG_TRY(ReadExactly(transport, head, sizeof(head), deadline));
    if (head[0] != 0x05 || head[1] != 0x00 || head[2] != 0x00) return SG_PROXY_ERROR;
    // Consume the bound address so no reply bytes leak into the TLS stream.
    size_t addr_len = 0;
    switch (head[3]) {
    case 0x01: addr_len = 4; break;
    case 0x04: addr_len = 16; break;
    case 0x03: {
        uint8_t len = 0;
        SG_TRY(ReadExactly(transport, &len, 1, deadline));
        addr_len = len;
        break;
    }
    default:
        return SG_PROXY_ERROR;
    }
    uint8_t rest[256 + 2];
    SG_TRY(ReadExactly(transport, rest, addr_len + 2, deadline));
    return OkStatus();
}

// ---- configuration parsing ---------------------------------------------------------------

Status ParseProxyUrl(const std::string& url_in, ResolvedProxy* out)
{
    if (out == nullptr) return SG_INVALID_ARGUMENT;
    const std::string url = Trim(url_in);
    if (url.empty() || url.size() > 1024 || HasControlOrSeparator(url)) return SG_INVALID_ARGUMENT;
    std::string scheme = "http";
    std::string rest = url;
    const size_t sep = url.find("://");
    if (sep != std::string::npos) {
        scheme = ToLower(url.substr(0, sep));
        rest = url.substr(sep + 3);
    }
    uint16_t default_port;
    if (scheme == "http") {
        out->type = SG_PROXY_TYPE_HTTP_CONNECT;
        default_port = 8080;
    } else if (scheme == "socks5" || scheme == "socks5h") {
        out->type = SG_PROXY_TYPE_SOCKS5;
        default_port = 1080;
    } else if (scheme == "socks4a" || scheme == "socks4") {
        out->type = SG_PROXY_TYPE_SOCKS4A;
        default_port = 1080;
    } else {
        return SG_NOT_SUPPORTED;  // e.g. https:// proxies (TLS to the proxy) are not supported
    }
    const size_t slash = rest.find('/');
    if (slash != std::string::npos) rest = rest.substr(0, slash);
    const size_t at = rest.rfind('@');
    if (at != std::string::npos) {
        const std::string userinfo = rest.substr(0, at);
        rest = rest.substr(at + 1);
        const size_t colon = userinfo.find(':');
        out->username = userinfo.substr(0, colon);
        if (colon != std::string::npos) {
            const std::string pw = userinfo.substr(colon + 1);
            out->password.assign(pw.begin(), pw.end());
        }
        if (out->username.size() > kMaxProxyField || out->password.size() > kMaxProxyField) return SG_INVALID_ARGUMENT;
    }
    return ParseHostPort(rest, default_port, &out->host, &out->port);
}

Status ParseWindowsProxyList(const std::string& list, ResolvedProxy* out)
{
    if (out == nullptr) return SG_INVALID_ARGUMENT;
    const std::string text = Trim(list);
    if (text.empty()) return SG_NOT_FOUND;
    if (text.find('=') == std::string::npos) {
        // One proxy for every protocol.
        const size_t sep = text.find_first_of("; ");
        return ParseProxyUrl(text.substr(0, sep), out);
    }
    std::string https;
    std::string http;
    std::string socks;
    size_t pos = 0;
    while (pos <= text.size()) {
        const size_t end = text.find_first_of("; ", pos);
        const std::string item = text.substr(pos, end == std::string::npos ? std::string::npos : end - pos);
        const size_t eq = item.find('=');
        if (eq != std::string::npos) {
            const std::string key = ToLower(Trim(item.substr(0, eq)));
            const std::string value = Trim(item.substr(eq + 1));
            if (key == "https") https = value;
            if (key == "http") http = value;
            if (key == "socks") socks = value;
        }
        if (end == std::string::npos) break;
        pos = end + 1;
    }
    if (!https.empty()) return ParseProxyUrl(https, out);
    if (!socks.empty()) return ParseProxyUrl("socks4a://" + socks, out);  // WinINet "socks=" means SOCKS4
    if (!http.empty()) return ParseProxyUrl(http, out);
    return SG_NOT_FOUND;
}

bool MatchesProxyBypass(const std::string& host_in, const std::string& bypass_list)
{
    const std::string host = ToLower(host_in);
    size_t pos = 0;
    while (pos <= bypass_list.size()) {
        const size_t end = bypass_list.find_first_of(",; ", pos);
        std::string entry = ToLower(Trim(bypass_list.substr(pos, end == std::string::npos ? std::string::npos : end - pos)));
        if (!entry.empty()) {
            if (entry == "*") return true;
            if (entry == "<local>" && host.find('.') == std::string::npos) return true;
            if (entry.compare(0, 2, "*.") == 0) entry = entry.substr(1);
            if (entry[0] == '.') {
                if (host.size() > entry.size() && host.compare(host.size() - entry.size(), entry.size(), entry) == 0) {
                    return true;
                }
                if (host == entry.substr(1)) return true;
            } else if (host == entry) {
                return true;
            } else if (host.size() > entry.size() && host.compare(host.size() - entry.size(), entry.size(), entry) == 0 &&
                       host[host.size() - entry.size() - 1] == '.') {
                return true;  // curl-style: "example.com" also matches "a.example.com"
            }
        }
        if (end == std::string::npos) break;
        pos = end + 1;
    }
    return false;
}

}  // namespace sg::client
