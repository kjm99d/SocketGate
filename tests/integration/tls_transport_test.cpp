// Phase 2: TLS over real sockets. Server = IIoService + TLS engine (memory BIOs),
// client = TcpTransport + TlsChannel.
#include "sg_test.h"

#include "support/test_pki.h"
#include "tls/tls_channel.h"
#include "transport/io_service.h"
#include "transport/tcp_transport.h"

#include <algorithm>
#include <atomic>
#include <chrono>
#include <cstring>
#include <future>
#include <mutex>
#include <random>
#include <thread>

using namespace sg;
using namespace sgtest;
using sg::server::AsyncStream;

namespace {

class TlsEchoSession : public std::enable_shared_from_this<TlsEchoSession> {
public:
    TlsEchoSession(std::shared_ptr<AsyncStream> stream, std::unique_ptr<tls::ITlsEngine> engine)
        : stream_(std::move(stream)), engine_(std::move(engine))
    {
    }

    void Read()
    {
        auto self = shared_from_this();
        const Status st = stream_->AsyncRead([self](Status status, const uint8_t* data, size_t size) {
            if (!status.ok() || !self->OnData(ByteView(data, size))) {
                self->stream_->Close();
                return;
            }
            self->Read();
        });
        if (!st.ok()) stream_->Close();
    }

private:
    bool OnData(ByteView data)
    {
        std::lock_guard<std::mutex> lock(mutex_);
        if (!engine_->FeedIncoming(data).ok()) return false;
        if (!engine_->IsHandshakeComplete()) {
            const Status hs = engine_->Handshake();
            Flush();
            if (hs == kStatusWouldBlock) return true;
            if (!hs.ok()) return false;
        }
        uint8_t buf[8192];
        for (;;) {
            size_t n = 0;
            const Status st = engine_->Read(buf, sizeof(buf), &n);
            if (st == kStatusWouldBlock) break;
            if (!st.ok()) {
                Flush();
                return false;
            }
            if (!engine_->Write(ByteView(buf, n)).ok()) return false;
        }
        Flush();
        return true;
    }

    void Flush()
    {
        Bytes out;
        engine_->TakeOutgoing(&out);
        if (!out.empty()) stream_->AsyncWrite(std::move(out), nullptr).IgnoreError();
    }

    std::shared_ptr<AsyncStream> stream_;
    std::mutex mutex_;
    std::unique_ptr<tls::ITlsEngine> engine_;
};

struct TlsEchoServer {
    TestCert ca = CreateRootCa("SockGate Test CA");
    TestCert leaf = IssueLocalhostServer(ca);
    std::shared_ptr<tls::ITlsContext> ctx;
    std::unique_ptr<server::IIoService> io = server::CreateIoService();
    uint16_t port = 0;

    enum class Mode { kTls, kSilent, kGarbage };

    void Start(Mode mode = Mode::kTls)
    {
        SG_ASSERT_OK(tls::DefaultTlsProvider().CreateServerContext(ServerConfigFor(leaf), &ctx));
        SG_ASSERT_OK(io->Start({}));
        SG_ASSERT_OK(io->Listen("127.0.0.1", 0,
                                [this, mode](std::shared_ptr<AsyncStream> stream) {
                                    if (mode == Mode::kSilent) {
                                        std::lock_guard<std::mutex> lock(held_mutex);
                                        held.push_back(std::move(stream));
                                        return;
                                    }
                                    if (mode == Mode::kGarbage) {
                                        std::string junk = "HTTP/1.1 200 OK\r\nContent-Length: 0\r\n\r\n";
                                        stream->AsyncWrite(Bytes(junk.begin(), junk.end()), nullptr).IgnoreError();
                                        std::lock_guard<std::mutex> lock(held_mutex);
                                        held.push_back(std::move(stream));
                                        return;
                                    }
                                    std::unique_ptr<tls::ITlsEngine> engine;
                                    if (!ctx->CreateEngine(&engine).ok()) {
                                        stream->Close();
                                        return;
                                    }
                                    std::make_shared<TlsEchoSession>(std::move(stream), std::move(engine))->Read();
                                },
                                &port));
    }

    ~TlsEchoServer()
    {
        io->Stop();
        held.clear();
    }

    std::mutex held_mutex;
    std::vector<std::shared_ptr<AsyncStream>> held;
};

std::unique_ptr<client::TlsChannel> Connect(const TestCert& trust, uint16_t port, Status* status,
                                            uint32_t handshake_timeout_ms = 5000)
{
    std::shared_ptr<tls::ITlsContext> ctx;
    *status = tls::DefaultTlsProvider().CreateClientContext(ClientConfigTrusting(trust), &ctx);
    if (!status->ok()) return nullptr;
    client::TcpTransportOptions opts;
    opts.connect_timeout_ms = 5000;
    opts.io_timeout_ms = 10000;
    auto transport = std::make_unique<client::TcpTransport>(opts);
    *status = transport->Connect({"localhost", port});
    if (!status->ok()) return nullptr;
    std::unique_ptr<tls::ITlsEngine> engine;
    *status = ctx->CreateEngine(&engine);
    if (!status->ok()) return nullptr;
    auto channel = std::make_unique<client::TlsChannel>(std::move(transport), std::move(engine));
    *status = channel->Handshake(handshake_timeout_ms);
    return channel;
}

}  // namespace

SG_TEST(TlsOverSockets, ConcurrentSendAndReceive)
{
    TlsEchoServer server;
    server.Start();
    Status st;
    auto channel = Connect(server.ca, server.port, &st);
    SG_ASSERT_OK(st);
    SG_EXPECT(channel->SessionInfo().tls13);

    std::mt19937 rng(42);
    Bytes payload(512 * 1024);
    for (auto& b : payload) b = static_cast<uint8_t>(rng());

    // Sender and receiver run on different threads over the same channel.
    auto sender = std::async(std::launch::async, [&]() {
        for (size_t off = 0; off < payload.size(); off += 7000) {
            const size_t n = std::min<size_t>(7000, payload.size() - off);
            SG_TRY(channel->Send(payload.data() + off, n));
        }
        return OkStatus();
    });
    Bytes echoed;
    echoed.reserve(payload.size());
    uint8_t buf[16384];
    while (echoed.size() < payload.size()) {
        size_t n = 0;
        const Status rst = channel->Receive(buf, sizeof(buf), &n, 10000);
        SG_ASSERT_OK(rst);
        echoed.insert(echoed.end(), buf, buf + n);
    }
    SG_EXPECT_OK(sender.get());
    SG_EXPECT(echoed == payload);
    channel->Shutdown();
}

SG_TEST(TlsOverSockets, ReconnectAfterDisconnect)
{
    TlsEchoServer server;
    server.Start();
    for (int i = 0; i < 3; ++i) {
        Status st;
        auto channel = Connect(server.ca, server.port, &st);
        SG_ASSERT_OK(st);
        const uint8_t msg[] = {'h', 'i', static_cast<uint8_t>('0' + i)};
        SG_ASSERT_OK(channel->Send(msg, sizeof(msg)));
        uint8_t buf[8];
        size_t got = 0;
        while (got < sizeof(msg)) {
            size_t n = 0;
            SG_ASSERT_OK(channel->Receive(buf + got, sizeof(buf) - got, &n, 5000));
            got += n;
        }
        SG_EXPECT(std::memcmp(buf, msg, sizeof(msg)) == 0);
        channel->Shutdown();
    }
}

SG_TEST(TlsOverSockets, WrongTrustAnchorFails)
{
    TlsEchoServer server;
    server.Start();
    const TestCert other = CreateRootCa("Other CA");
    Status st;
    auto channel = Connect(other, server.port, &st);
    SG_EXPECT_STATUS(st, SG_CERTIFICATE_ERROR);
}

SG_TEST(TlsOverSockets, SilentServerTimesOut)
{
    TlsEchoServer server;
    server.Start(TlsEchoServer::Mode::kSilent);
    Status st;
    const auto start = std::chrono::steady_clock::now();
    auto channel = Connect(server.ca, server.port, &st, 400);
    const auto ms = std::chrono::duration_cast<std::chrono::milliseconds>(std::chrono::steady_clock::now() - start).count();
    SG_EXPECT_STATUS(st, SG_TIMEOUT);
    SG_EXPECT(ms < 4000);
}

SG_TEST(TlsOverSockets, NonTlsServerFails)
{
    TlsEchoServer server;
    server.Start(TlsEchoServer::Mode::kGarbage);
    Status st;
    auto channel = Connect(server.ca, server.port, &st);
    SG_EXPECT_STATUS(st, SG_TLS_ERROR);
}

SG_TEST(TlsOverSockets, AbortWakesBlockedReceive)
{
    TlsEchoServer server;
    server.Start();
    Status st;
    auto channel = Connect(server.ca, server.port, &st);
    SG_ASSERT_OK(st);
    auto blocked = std::async(std::launch::async, [&]() {
        uint8_t buf[16];
        size_t n = 0;
        return channel->Receive(buf, sizeof(buf), &n, net::kNoTimeout);
    });
    std::this_thread::sleep_for(std::chrono::milliseconds(100));
    channel->Abort();
    SG_ASSERT(blocked.wait_for(std::chrono::seconds(5)) == std::future_status::ready);
    SG_EXPECT_STATUS(blocked.get(), SG_CLOSED);
}
