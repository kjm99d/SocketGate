#include "support/test_proxy.h"

#include "tls/tls_channel.h"
#include "transport/tcp_transport.h"

#include "sockgate_common/core/clock.h"

#include <chrono>
#include <cstring>
#include <stdexcept>

namespace sgtest {
namespace {

using sg::Status;

std::string StdBase64(const std::string& in)
{
    static const char* kAlphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    std::string out;
    size_t i = 0;
    for (; i + 3 <= in.size(); i += 3) {
        const uint32_t v = (static_cast<uint32_t>(static_cast<uint8_t>(in[i])) << 16) | (static_cast<uint32_t>(static_cast<uint8_t>(in[i + 1])) << 8) |
                           static_cast<uint32_t>(static_cast<uint8_t>(in[i + 2]));
        out += kAlphabet[(v >> 18) & 63];
        out += kAlphabet[(v >> 12) & 63];
        out += kAlphabet[(v >> 6) & 63];
        out += kAlphabet[v & 63];
    }
    if (in.size() - i == 1) {
        const uint32_t v = static_cast<uint32_t>(static_cast<uint8_t>(in[i])) << 16;
        out += kAlphabet[(v >> 18) & 63];
        out += kAlphabet[(v >> 12) & 63];
        out += "==";
    } else if (in.size() - i == 2) {
        const uint32_t v = (static_cast<uint32_t>(static_cast<uint8_t>(in[i])) << 16) | (static_cast<uint32_t>(static_cast<uint8_t>(in[i + 1])) << 8);
        out += kAlphabet[(v >> 18) & 63];
        out += kAlphabet[(v >> 12) & 63];
        out += kAlphabet[(v >> 6) & 63];
        out += '=';
    }
    return out;
}

sg::platform::NativeSocket OpenListener(uint16_t* port)
{
    std::vector<sg::platform::SocketAddress> addrs;
    if (!sg::platform::ResolveAddresses("127.0.0.1", 0, true, &addrs).ok()) throw std::runtime_error("resolve");
    sg::platform::NativeSocket s = sg::platform::kInvalidSocket;
    if (!sg::platform::CreateListener(addrs.front(), 16, false, &s).ok()) throw std::runtime_error("listen");
    sg::platform::SocketAddress local;
    if (!sg::platform::GetLocalAddress(s, &local).ok()) throw std::runtime_error("getsockname");
    *port = local.Port();
    return s;
}

bool ReadExact(sg::net::ITransport& t, uint8_t* out, size_t n)
{
    size_t got = 0;
    while (got < n) {
        size_t r = 0;
        if (!t.ReceiveFor(out + got, n - got, &r, 5000).ok()) return false;
        got += r;
    }
    return true;
}

bool SendAll(sg::net::ITransport& t, const std::string& s)
{
    return t.Send(reinterpret_cast<const uint8_t*>(s.data()), s.size()).ok();
}

bool SendBytes(sg::net::ITransport& t, const std::vector<uint8_t>& b) { return t.Send(b.data(), b.size()).ok(); }

// Copies bytes from `from` to `to` until either side fails, recording them.
void Pump(sg::net::ITransport& from, sg::net::ITransport& to, std::mutex* capture_mutex, std::string* capture)
{
    uint8_t buf[16384];
    for (;;) {
        size_t n = 0;
        if (!from.ReceiveFor(buf, sizeof(buf), &n, sg::net::kNoTimeout).ok()) break;
        if (capture != nullptr) {
            std::lock_guard<std::mutex> lock(*capture_mutex);
            capture->append(reinterpret_cast<const char*>(buf), n);
        }
        if (!to.Send(buf, n).ok()) break;
    }
    from.Shutdown();
    to.Shutdown();
}

}  // namespace

// ---- SocketTransport --------------------------------------------------------------------

Status SocketTransport::Send(const uint8_t* data, size_t size)
{
    return SendFor(data, size, sg::net::kNoTimeout);
}

Status SocketTransport::SendFor(const uint8_t* data, size_t size, uint32_t timeout_ms)
{
    const sg::Deadline deadline(timeout_ms);
    size_t off = 0;
    while (off < size) {
        if (deadline.Expired()) return SG_TIMEOUT;
        size_t sent = 0;
        const Status st = sg::platform::SendSome(socket_, data + off, size - off, &sent);
        if (st == sg::kStatusWouldBlock) {
            bool ready = false;
            SG_TRY(sg::platform::WaitSocket(socket_, sg::platform::WaitFor::kWrite, 200, &ready));
            continue;
        }
        SG_TRY(st);
        off += sent;
    }
    return sg::OkStatus();
}

Status SocketTransport::Receive(uint8_t* buffer, size_t capacity, size_t* received)
{
    return ReceiveFor(buffer, capacity, received, sg::net::kNoTimeout);
}

Status SocketTransport::ReceiveFor(uint8_t* buffer, size_t capacity, size_t* received, uint32_t timeout_ms)
{
    const sg::Deadline deadline(timeout_ms);
    for (;;) {
        {
            std::lock_guard<std::mutex> lock(mutex_);
            if (closed_) return SG_CLOSED;
        }
        bool ready = false;
        SG_TRY(sg::platform::WaitSocket(socket_, sg::platform::WaitFor::kRead, deadline.RemainingMs(200), &ready));
        if (ready) {
            const Status st = sg::platform::ReceiveSome(socket_, buffer, capacity, received);
            if (st == sg::kStatusWouldBlock) continue;
            return st;
        }
        if (deadline.Expired()) return SG_TIMEOUT;
    }
}

void SocketTransport::Shutdown() noexcept
{
    std::lock_guard<std::mutex> lock(mutex_);
    if (!closed_) sg::platform::ShutdownSocket(socket_);
}

void SocketTransport::Close() noexcept
{
    std::lock_guard<std::mutex> lock(mutex_);
    if (closed_) return;
    closed_ = true;
    sg::platform::ShutdownSocket(socket_);
    sg::platform::CloseSocket(socket_);
}

// ---- TestProxy -------------------------------------------------------------------------

TestProxy::TestProxy(Options options) : options_(std::move(options))
{
    listener_ = OpenListener(&port_);
    acceptor_ = std::thread([this]() { AcceptLoop(); });
}

TestProxy::~TestProxy()
{
    stopping_ = true;
    sg::platform::ShutdownSocket(listener_);
    sg::platform::CloseSocket(listener_);
    if (acceptor_.joinable()) acceptor_.join();
    std::vector<std::thread> workers;
    {
        std::lock_guard<std::mutex> lock(mutex_);
        for (auto& t : live_) t->Shutdown();
        workers.swap(workers_);
    }
    for (auto& w : workers) w.join();
}

std::string TestProxy::last_target()
{
    std::lock_guard<std::mutex> lock(mutex_);
    return last_target_;
}

std::string TestProxy::captured()
{
    std::lock_guard<std::mutex> lock(mutex_);
    return captured_;
}

void TestProxy::AcceptLoop()
{
    while (!stopping_.load()) {
        sg::platform::NativeSocket client = sg::platform::kInvalidSocket;
        if (!sg::platform::AcceptConnection(listener_, &client, nullptr).ok()) {
            if (stopping_.load()) return;
            continue;
        }
        std::lock_guard<std::mutex> lock(mutex_);
        workers_.emplace_back([this, client]() { Serve(client); });
    }
}

bool TestProxy::Negotiate(SocketTransport& client, std::string* host, uint16_t* port)
{
    if (options_.kind == Kind::kHttpConnect) {
        std::string header;
        while (header.size() < 4 || header.compare(header.size() - 4, 4, "\r\n\r\n") != 0) {
            uint8_t b;
            if (header.size() > 16384 || !ReadExact(client, &b, 1)) return false;
            header.push_back(static_cast<char>(b));
        }
        switch (options_.misbehaviour) {
        case Misbehaviour::kRefuse:
            SendAll(client, "HTTP/1.1 403 Forbidden\r\nContent-Length: 0\r\n\r\n");
            return false;
        case Misbehaviour::kGarbage:
            SendAll(client, "SSH-2.0-OpenSSH_9.0\r\n\r\n");
            return false;
        case Misbehaviour::kHugeHeader:
            SendAll(client, "HTTP/1.1 200 OK\r\nX-Pad: " + std::string(9000, 'a') + "\r\n\r\n");
            return false;
        case Misbehaviour::kSilent:
            while (!stopping_.load()) std::this_thread::sleep_for(std::chrono::milliseconds(20));
            return false;
        case Misbehaviour::kNone:
            break;
        }
        if (header.compare(0, 8, "CONNECT ") != 0) return false;
        const size_t sp = header.find(' ', 8);
        const std::string authority = header.substr(8, sp - 8);
        const size_t colon = authority.rfind(':');
        *host = authority.substr(0, colon);
        *port = static_cast<uint16_t>(std::stoi(authority.substr(colon + 1)));
        if (!options_.required_user.empty()) {
            const std::string expected =
                "Proxy-Authorization: Basic " + StdBase64(options_.required_user + ":" + options_.required_password) + "\r\n";
            if (header.find(expected) == std::string::npos) {
                SendAll(client, "HTTP/1.1 407 Proxy Authentication Required\r\n\r\n");
                return false;
            }
        }
        return true;  // "200" is sent after the upstream connect succeeded
    }

    if (options_.kind == Kind::kSocks4a) {
        uint8_t head[8];
        if (!ReadExact(client, head, sizeof(head)) || head[0] != 0x04 || head[1] != 0x01) return false;
        *port = static_cast<uint16_t>((head[2] << 8) | head[3]);
        std::string user;
        std::string name;
        uint8_t b;
        while (ReadExact(client, &b, 1) && b != 0) user.push_back(static_cast<char>(b));
        while (ReadExact(client, &b, 1) && b != 0) name.push_back(static_cast<char>(b));
        *host = name;
        if (options_.misbehaviour == Misbehaviour::kRefuse) {
            SendBytes(client, {0x00, 0x5B, 0, 0, 0, 0, 0, 0});
            return false;
        }
        return true;
    }

    // SOCKS5
    uint8_t greet[2];
    if (!ReadExact(client, greet, 2) || greet[0] != 0x05) return false;
    std::vector<uint8_t> methods(greet[1]);
    if (!methods.empty() && !ReadExact(client, methods.data(), methods.size())) return false;
    const uint8_t wanted = options_.required_user.empty() ? 0x00 : 0x02;
    bool offered = false;
    for (uint8_t m : methods) offered = offered || m == wanted;
    if (!offered) {
        SendBytes(client, {0x05, 0xFF});
        return false;
    }
    SendBytes(client, {0x05, wanted});
    if (wanted == 0x02) {
        uint8_t v[2];
        if (!ReadExact(client, v, 2)) return false;
        std::string user(v[1], '\0');
        if (!ReadExact(client, reinterpret_cast<uint8_t*>(&user[0]), user.size())) return false;
        uint8_t plen;
        if (!ReadExact(client, &plen, 1)) return false;
        std::string pass(plen, '\0');
        if (plen != 0 && !ReadExact(client, reinterpret_cast<uint8_t*>(&pass[0]), pass.size())) return false;
        const bool ok = user == options_.required_user && pass == options_.required_password;
        SendBytes(client, {0x01, static_cast<uint8_t>(ok ? 0x00 : 0x01)});
        if (!ok) return false;
    }
    uint8_t req[5];
    if (!ReadExact(client, req, sizeof(req)) || req[0] != 0x05 || req[1] != 0x01 || req[3] != 0x03) return false;
    std::string name(req[4], '\0');
    uint8_t port_bytes[2];
    if (!ReadExact(client, reinterpret_cast<uint8_t*>(&name[0]), name.size()) || !ReadExact(client, port_bytes, 2)) {
        return false;
    }
    *host = name;
    *port = static_cast<uint16_t>((port_bytes[0] << 8) | port_bytes[1]);
    if (options_.misbehaviour == Misbehaviour::kRefuse) {
        SendBytes(client, {0x05, 0x05, 0x00, 0x01, 0, 0, 0, 0, 0, 0});  // connection refused
        return false;
    }
    return true;
}

void TestProxy::Serve(sg::platform::NativeSocket socket)
{
    auto client = std::make_shared<SocketTransport>(socket);
    {
        std::lock_guard<std::mutex> lock(mutex_);
        live_.push_back(client);
    }
    std::string host;
    uint16_t port = 0;
    if (!Negotiate(*client, &host, &port)) {
        client->Close();
        return;
    }
    sg::client::TcpTransportOptions opts;
    opts.connect_timeout_ms = 5000;
    opts.io_timeout_ms = 0;
    auto upstream = std::make_shared<sg::client::TcpTransport>(opts);
    const bool connected = upstream->Connect({host, port}).ok();
    {
        std::lock_guard<std::mutex> lock(mutex_);
        live_.push_back(upstream);
        last_target_ = host + ":" + std::to_string(port);
    }
    switch (options_.kind) {
    case Kind::kHttpConnect:
        SendAll(*client, connected ? "HTTP/1.1 200 Connection established\r\n\r\n" : "HTTP/1.1 502 Bad Gateway\r\n\r\n");
        break;
    case Kind::kSocks4a:
        SendBytes(*client, {0x00, static_cast<uint8_t>(connected ? 0x5A : 0x5B), 0, 0, 0, 0, 0, 0});
        break;
    case Kind::kSocks5:
        SendBytes(*client, {0x05, static_cast<uint8_t>(connected ? 0x00 : 0x05), 0x00, 0x01, 0, 0, 0, 0, 0, 0});
        break;
    }
    if (!connected) {
        client->Close();
        return;
    }
    tunnels_.fetch_add(1);
    std::thread up([&]() { Pump(*client, *upstream, &mutex_, &captured_); });
    Pump(*upstream, *client, &mutex_, &captured_);
    up.join();
    client->Close();
    upstream->Close();
}

// ---- TlsMitmRelay ----------------------------------------------------------------------

TlsMitmRelay::TlsMitmRelay(const TestCert& impostor, const TestCert& real_ca, uint16_t real_port)
    : impostor_(impostor), real_ca_(real_ca), real_port_(real_port)
{
    listener_ = OpenListener(&port_);
    acceptor_ = std::thread([this]() { AcceptLoop(); });
}

TlsMitmRelay::~TlsMitmRelay()
{
    stopping_ = true;
    sg::platform::ShutdownSocket(listener_);
    sg::platform::CloseSocket(listener_);
    if (acceptor_.joinable()) acceptor_.join();
    std::vector<std::thread> workers;
    {
        std::lock_guard<std::mutex> lock(mutex_);
        for (auto& t : live_) t->Shutdown();
        workers.swap(workers_);
    }
    for (auto& w : workers) w.join();
}

void TlsMitmRelay::AcceptLoop()
{
    while (!stopping_.load()) {
        sg::platform::NativeSocket client = sg::platform::kInvalidSocket;
        if (!sg::platform::AcceptConnection(listener_, &client, nullptr).ok()) {
            if (stopping_.load()) return;
            continue;
        }
        std::lock_guard<std::mutex> lock(mutex_);
        workers_.emplace_back([this, client]() { Serve(client); });
    }
}

void TlsMitmRelay::Serve(sg::platform::NativeSocket socket)
{
    auto down_transport = std::make_shared<SocketTransport>(socket);
    sg::client::TcpTransportOptions opts;
    opts.connect_timeout_ms = 5000;
    opts.io_timeout_ms = 0;
    auto up_transport = std::make_shared<sg::client::TcpTransport>(opts);
    {
        std::lock_guard<std::mutex> lock(mutex_);
        live_.push_back(down_transport);
        live_.push_back(up_transport);
    }

    // Victim-facing TLS with the impostor certificate.
    std::shared_ptr<sg::tls::ITlsContext> server_ctx;
    std::unique_ptr<sg::tls::ITlsEngine> server_engine;
    if (!sg::tls::DefaultTlsProvider().CreateServerContext(ServerConfigFor(impostor_), &server_ctx).ok() ||
        !server_ctx->CreateEngine(&server_engine).ok()) {
        return;
    }
    sg::client::TlsChannel down(down_transport, std::move(server_engine));
    if (!down.Handshake(5000).ok()) return;

    // Genuine TLS session to the real server.
    std::shared_ptr<sg::tls::ITlsContext> client_ctx;
    std::unique_ptr<sg::tls::ITlsEngine> client_engine;
    if (!up_transport->Connect({"127.0.0.1", real_port_}).ok() ||
        !sg::tls::DefaultTlsProvider().CreateClientContext(ClientConfigTrusting(real_ca_, "127.0.0.1"), &client_ctx).ok() ||
        !client_ctx->CreateEngine(&client_engine).ok()) {
        return;
    }
    sg::client::TlsChannel up(up_transport, std::move(client_engine));
    if (!up.Handshake(5000).ok()) return;
    sessions_.fetch_add(1);

    // Relay the decrypted SockGate stream verbatim.
    auto relay = [](sg::client::TlsChannel& from, sg::client::TlsChannel& to) {
        uint8_t buf[16384];
        for (;;) {
            size_t n = 0;
            if (!from.Receive(buf, sizeof(buf), &n, sg::net::kNoTimeout).ok()) break;
            if (!to.Send(buf, n).ok()) break;
        }
        from.Abort();
        to.Abort();
    };
    std::thread t([&]() { relay(down, up); });
    relay(up, down);
    t.join();
}

}  // namespace sgtest
