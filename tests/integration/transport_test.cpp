// Phase 1: cross-platform transport. The server side uses the platform
// IIoService (IOCP / epoll); the client side uses the blocking TcpTransport.
#include "sg_test.h"

#include "transport/io_service.h"
#include "transport/tcp_transport.h"

#include <atomic>
#include <chrono>
#include <cstring>
#include <future>
#include <memory>
#include <mutex>
#include <random>
#include <thread>
#include <vector>

using sg::Status;
using sg::client::TcpTransport;
using sg::client::TcpTransportOptions;
using sg::server::AsyncStream;
using sg::server::IIoService;

namespace {

class EchoSession : public std::enable_shared_from_this<EchoSession> {
public:
    explicit EchoSession(std::shared_ptr<AsyncStream> stream) : stream_(std::move(stream)) {}

    void Read()
    {
        auto self = shared_from_this();
        const Status st = stream_->AsyncRead([self](Status status, const uint8_t* data, size_t size) {
            if (!status.ok()) {
                self->stream_->Close();
                return;
            }
            std::vector<uint8_t> copy(data, data + size);  // data is only valid until the next read
            if (!self->stream_->AsyncWrite(std::move(copy), nullptr).ok()) return;
            self->Read();
        });
        if (!st.ok()) stream_->Close();
    }

private:
    std::shared_ptr<AsyncStream> stream_;
};

struct EchoServer {
    std::unique_ptr<IIoService> io = sg::server::CreateIoService();
    uint16_t port = 0;
    std::mutex held_mutex;
    std::vector<std::shared_ptr<AsyncStream>> held;  // silent streams kept open by the test

    ~EchoServer()
    {
        io->Stop();
        held.clear();  // streams must not outlive the service
    }

    void Start(bool echo = true)
    {
        sg::server::IoServiceOptions options;
        options.worker_threads = 4;
        SG_ASSERT_OK(io->Start(options));
        SG_ASSERT_OK(io->Listen("127.0.0.1", 0,
                                [this, echo](std::shared_ptr<AsyncStream> stream) {
                                    if (echo) {
                                        std::make_shared<EchoSession>(std::move(stream))->Read();
                                    } else {
                                        std::lock_guard<std::mutex> lock(held_mutex);
                                        held.push_back(std::move(stream));
                                    }
                                },
                                &port));
        SG_ASSERT(port != 0);
    }
};

std::vector<uint8_t> RandomBytes(size_t n, uint32_t seed)
{
    std::mt19937 rng(seed);
    std::vector<uint8_t> v(n);
    for (auto& b : v) b = static_cast<uint8_t>(rng());
    return v;
}

Status ReceiveExactly(TcpTransport& t, uint8_t* out, size_t size)
{
    size_t got = 0;
    while (got < size) {
        size_t n = 0;
        SG_TRY(t.Receive(out + got, size - got, &n));
        got += n;
    }
    return sg::OkStatus();
}

TcpTransportOptions FastOptions()
{
    TcpTransportOptions o;
    o.connect_timeout_ms = 5000;
    o.io_timeout_ms = 10000;
    return o;
}

}  // namespace

SG_TEST(Transport, EchoRoundTrip)
{
    EchoServer server;
    server.Start();

    TcpTransport client(FastOptions());
    SG_ASSERT_OK(client.Connect({"127.0.0.1", server.port}));
    SG_EXPECT(!client.PeerAddress().empty());

    const auto payload = RandomBytes(256 * 1024, 1);
    SG_ASSERT_OK(client.Send(payload.data(), payload.size()));
    std::vector<uint8_t> echoed(payload.size());
    SG_ASSERT_OK(ReceiveExactly(client, echoed.data(), echoed.size()));
    SG_EXPECT(echoed == payload);

    client.Close();
    server.io->Stop();
}

SG_TEST(Transport, ManyConcurrentClients)
{
    EchoServer server;
    server.Start();

    constexpr int kClients = 24;
    std::atomic<int> ok_count{0};
    std::vector<std::thread> threads;
    for (int i = 0; i < kClients; ++i) {
        threads.emplace_back([&, i]() {
            TcpTransport client(FastOptions());
            if (!client.Connect({"127.0.0.1", server.port}).ok()) return;
            const auto payload = RandomBytes(64 * 1024 + static_cast<size_t>(i), static_cast<uint32_t>(100 + i));
            // Interleave sends and receives in chunks to exercise partial I/O.
            size_t sent = 0;
            std::vector<uint8_t> echoed(payload.size());
            size_t received = 0;
            while (received < payload.size()) {
                if (sent < payload.size()) {
                    const size_t chunk = std::min<size_t>(4096, payload.size() - sent);
                    if (!client.Send(payload.data() + sent, chunk).ok()) return;
                    sent += chunk;
                }
                size_t n = 0;
                if (!client.Receive(echoed.data() + received, payload.size() - received, &n).ok()) return;
                received += n;
            }
            if (echoed == payload) ok_count.fetch_add(1);
        });
    }
    for (auto& t : threads) t.join();
    SG_EXPECT_EQ(ok_count.load(), kClients);
    server.io->Stop();
}

SG_TEST(Transport, ConnectionRefused)
{
    // Obtain a free port by binding and immediately stopping a listener.
    uint16_t port = 0;
    {
        EchoServer server;
        server.Start();
        port = server.port;
        server.io->Stop();
    }
    TcpTransport client(FastOptions());
    const Status st = client.Connect({"127.0.0.1", port});
    SG_EXPECT(st == SG_NETWORK_ERROR || st == SG_TIMEOUT);
}

SG_TEST(Transport, InvalidArguments)
{
    TcpTransport client(FastOptions());
    SG_EXPECT_STATUS(client.Connect({"", 80}), SG_INVALID_ARGUMENT);
    SG_EXPECT_STATUS(client.Connect({"127.0.0.1", 0}), SG_INVALID_ARGUMENT);
    uint8_t buf[4];
    size_t n = 0;
    SG_EXPECT_STATUS(client.Receive(nullptr, 4, &n), SG_INVALID_ARGUMENT);
    SG_EXPECT_STATUS(client.Receive(buf, 0, &n), SG_INVALID_ARGUMENT);
    SG_EXPECT_STATUS(client.Send(nullptr, 4), SG_INVALID_ARGUMENT);
    // Not connected yet.
    SG_EXPECT_STATUS(client.Send(buf, 4), SG_CLOSED);
}

SG_TEST(Transport, UnresolvableHost)
{
    TcpTransport client(FastOptions());
    SG_EXPECT_STATUS(client.Connect({"nonexistent.invalid", 443}), SG_NETWORK_ERROR);
}

SG_TEST(Transport, ReceiveTimeout)
{
    EchoServer server;
    server.Start(/*echo=*/false);

    TcpTransport client(FastOptions());
    SG_ASSERT_OK(client.Connect({"127.0.0.1", server.port}));
    uint8_t buf[16];
    size_t n = 0;
    const auto start = std::chrono::steady_clock::now();
    SG_EXPECT_STATUS(client.ReceiveFor(buf, sizeof(buf), &n, 300), SG_TIMEOUT);
    const auto elapsed = std::chrono::duration_cast<std::chrono::milliseconds>(std::chrono::steady_clock::now() - start);
    SG_EXPECT(elapsed.count() >= 250);
    SG_EXPECT(elapsed.count() < 3000);
    server.io->Stop();
}

SG_TEST(Transport, ShutdownWakesBlockedReceive)
{
    EchoServer server;
    server.Start(/*echo=*/false);

    TcpTransport client(FastOptions());
    SG_ASSERT_OK(client.Connect({"127.0.0.1", server.port}));

    auto blocked = std::async(std::launch::async, [&client]() {
        uint8_t buf[16];
        size_t n = 0;
        const auto start = std::chrono::steady_clock::now();
        const Status st = client.ReceiveFor(buf, sizeof(buf), &n, sg::net::kNoTimeout);
        const auto ms = std::chrono::duration_cast<std::chrono::milliseconds>(std::chrono::steady_clock::now() - start).count();
        return std::make_pair(st, ms);
    });
    std::this_thread::sleep_for(std::chrono::milliseconds(150));
    client.Shutdown();
    SG_ASSERT(blocked.wait_for(std::chrono::seconds(5)) == std::future_status::ready);
    const auto result = blocked.get();
    SG_EXPECT_STATUS(result.first, SG_CLOSED);
    SG_EXPECT(result.second < 2000);

    // Every later operation fails, and Close() does not hang.
    uint8_t b = 0;
    SG_EXPECT_STATUS(client.Send(&b, 1), SG_CLOSED);
    client.Close();
    server.io->Stop();
}

SG_TEST(Transport, PeerCloseIsReportedAsClosed)
{
    auto io = sg::server::CreateIoService();
    sg::server::IoServiceOptions options;
    options.worker_threads = 2;
    SG_ASSERT_OK(io->Start(options));
    uint16_t port = 0;
    SG_ASSERT_OK(io->Listen("127.0.0.1", 0, [](std::shared_ptr<AsyncStream> s) { s->Close(); }, &port));

    TcpTransport client(FastOptions());
    SG_ASSERT_OK(client.Connect({"127.0.0.1", port}));
    uint8_t buf[16];
    size_t n = 0;
    const Status st = client.ReceiveFor(buf, sizeof(buf), &n, 5000);
    // Orderly close yields SG_CLOSED; an abortive close may surface as a network error.
    SG_EXPECT(st == SG_CLOSED || st == SG_NETWORK_ERROR);
    io->Stop();
}

SG_TEST(IoService, GracefulCloseDeliversQueuedWrites)
{
    auto io = sg::server::CreateIoService();
    SG_ASSERT_OK(io->Start({}));
    uint16_t port = 0;
    const auto payload = RandomBytes(300 * 1024, 7);
    SG_ASSERT_OK(io->Listen("127.0.0.1", 0,
                            [&payload](std::shared_ptr<AsyncStream> s) {
                                std::vector<uint8_t> copy = payload;
                                if (s->AsyncWrite(std::move(copy), nullptr).ok()) s->CloseAfterWrites();
                            },
                            &port));

    TcpTransport client(FastOptions());
    SG_ASSERT_OK(client.Connect({"127.0.0.1", port}));
    std::vector<uint8_t> got(payload.size());
    SG_ASSERT_OK(ReceiveExactly(client, got.data(), got.size()));
    SG_EXPECT(got == payload);
    uint8_t extra = 0;
    size_t n = 0;
    SG_EXPECT_STATUS(client.ReceiveFor(&extra, 1, &n, 5000), SG_CLOSED);
    io->Stop();
}

SG_TEST(IoService, WriteHandlersAndReadAfterClose)
{
    auto io = sg::server::CreateIoService();
    SG_ASSERT_OK(io->Start({}));
    uint16_t port = 0;
    std::promise<std::shared_ptr<AsyncStream>> accepted;
    SG_ASSERT_OK(io->Listen("127.0.0.1", 0,
                            [&accepted](std::shared_ptr<AsyncStream> s) { accepted.set_value(std::move(s)); },
                            &port));
    TcpTransport client(FastOptions());
    SG_ASSERT_OK(client.Connect({"127.0.0.1", port}));
    auto stream = accepted.get_future().get();
    SG_ASSERT(stream != nullptr);

    std::promise<Status> write_done;
    SG_ASSERT_OK(stream->AsyncWrite({1, 2, 3}, [&write_done](Status st) { write_done.set_value(st); }));
    auto write_future = write_done.get_future();
    SG_ASSERT(write_future.wait_for(std::chrono::seconds(5)) == std::future_status::ready);
    SG_EXPECT_OK(write_future.get());

    SG_EXPECT_STATUS(stream->AsyncWrite({}, nullptr), SG_INVALID_ARGUMENT);

    // A pending read completes with SG_CLOSED when the stream is closed locally.
    std::promise<Status> read_done;
    SG_ASSERT_OK(stream->AsyncRead([&read_done](Status st, const uint8_t*, size_t) { read_done.set_value(st); }));
    SG_EXPECT_STATUS(stream->AsyncRead([](Status, const uint8_t*, size_t) {}), SG_INVALID_STATE);
    stream->Close();
    auto read_future = read_done.get_future();
    SG_ASSERT(read_future.wait_for(std::chrono::seconds(5)) == std::future_status::ready);
    SG_EXPECT_STATUS(read_future.get(), SG_CLOSED);
    SG_EXPECT(stream->IsClosed());
    SG_EXPECT_STATUS(stream->AsyncWrite({1}, nullptr), SG_CLOSED);
    SG_EXPECT_STATUS(stream->AsyncRead([](Status, const uint8_t*, size_t) {}), SG_CLOSED);
    io->Stop();
}

SG_TEST(IoService, PostRunsOnWorker)
{
    auto io = sg::server::CreateIoService();
    SG_ASSERT_OK(io->Start({}));
    std::promise<std::thread::id> ran;
    SG_ASSERT_OK(io->Post([&ran]() { ran.set_value(std::this_thread::get_id()); }));
    auto f = ran.get_future();
    SG_ASSERT(f.wait_for(std::chrono::seconds(5)) == std::future_status::ready);
    SG_EXPECT(f.get() != std::this_thread::get_id());
    io->Stop();
    SG_EXPECT_STATUS(io->Post([]() {}), SG_CLOSED);
}

SG_TEST(IoService, GracefulCloseWithUnreadInputDoesNotReset)
{
    // The server never reads what the client sent; closing must still deliver
    // the whole response followed by an orderly end-of-stream (no RST).
    auto io = sg::server::CreateIoService();
    SG_ASSERT_OK(io->Start({}));
    uint16_t port = 0;
    const auto response = RandomBytes(200 * 1024, 11);
    std::mutex held_mutex;
    std::vector<std::shared_ptr<AsyncStream>> held;
    std::promise<void> client_sent;
    auto client_sent_future = client_sent.get_future().share();
    SG_ASSERT_OK(io->Listen("127.0.0.1", 0,
                            [&](std::shared_ptr<AsyncStream> s) {
                                {
                                    std::lock_guard<std::mutex> lock(held_mutex);
                                    held.push_back(s);
                                }
                                // Respond only after the client's data is sitting unread in our buffer.
                                io->Post([s, &response, client_sent_future]() {
                                    client_sent_future.wait();
                                    std::this_thread::sleep_for(std::chrono::milliseconds(50));
                                    std::vector<uint8_t> copy = response;
                                    if (s->AsyncWrite(std::move(copy), nullptr).ok()) s->CloseAfterWrites();
                                }).IgnoreError();
                            },
                            &port));

    TcpTransport client(FastOptions());
    SG_ASSERT_OK(client.Connect({"127.0.0.1", port}));
    const auto unread = RandomBytes(32 * 1024, 12);
    SG_ASSERT_OK(client.Send(unread.data(), unread.size()));
    client_sent.set_value();

    std::vector<uint8_t> got(response.size());
    SG_ASSERT_OK(ReceiveExactly(client, got.data(), got.size()));
    SG_EXPECT(got == response);
    // Our shutdown lets the server's drain observe EOF and close the stream.
    client.Shutdown();
    for (int i = 0; i < 200 && io->StreamCount() > 0; ++i) std::this_thread::sleep_for(std::chrono::milliseconds(10));
    SG_EXPECT_EQ(io->StreamCount(), size_t{0});
    io->Stop();
    held.clear();
}

SG_TEST(IoService, SelfRepostingTaskDoesNotStallStop)
{
    auto io = sg::server::CreateIoService();
    SG_ASSERT_OK(io->Start({}));
    std::atomic<int> runs{0};
    std::function<void()> task;
    task = [&]() {
        runs.fetch_add(1);
        std::this_thread::sleep_for(std::chrono::milliseconds(1));
        io->Post(task).IgnoreError();
    };
    SG_ASSERT_OK(io->Post(task));
    std::this_thread::sleep_for(std::chrono::milliseconds(50));
    const auto start = std::chrono::steady_clock::now();
    io->Stop();
    const auto ms = std::chrono::duration_cast<std::chrono::milliseconds>(std::chrono::steady_clock::now() - start).count();
    SG_EXPECT(runs.load() > 0);
    SG_EXPECT(ms < 2000);
}

SG_TEST(IoService, ConcurrentStopIsSafe)
{
    EchoServer server;
    server.Start();
    TcpTransport client(FastOptions());
    SG_ASSERT_OK(client.Connect({"127.0.0.1", server.port}));
    std::thread a([&]() { server.io->Stop(); });
    std::thread b([&]() { server.io->Stop(); });
    a.join();
    b.join();
    SG_EXPECT_STATUS(server.io->Post([]() {}), SG_CLOSED);
}

SG_TEST(IoService, StopWithActiveConnectionsDoesNotHang)
{
    EchoServer server;
    server.Start();
    std::vector<std::unique_ptr<TcpTransport>> clients;
    for (int i = 0; i < 8; ++i) {
        auto c = std::make_unique<TcpTransport>(FastOptions());
        SG_ASSERT_OK(c->Connect({"127.0.0.1", server.port}));
        const uint8_t b = static_cast<uint8_t>(i);
        SG_ASSERT_OK(c->Send(&b, 1));
        clients.push_back(std::move(c));
    }
    // Give the server a moment to register every stream.
    for (int i = 0; i < 100 && server.io->StreamCount() < clients.size(); ++i) {
        std::this_thread::sleep_for(std::chrono::milliseconds(10));
    }
    const auto start = std::chrono::steady_clock::now();
    server.io->Stop();
    const auto ms = std::chrono::duration_cast<std::chrono::milliseconds>(std::chrono::steady_clock::now() - start).count();
    SG_EXPECT(ms < 5000);
    SG_EXPECT_EQ(server.io->StreamCount(), size_t{0});

    for (auto& c : clients) {
        uint8_t buf[8];
        size_t n = 0;
        Status st = sg::OkStatus();
        // Drain the echoed byte (if it arrived) and then expect end-of-stream.
        for (int i = 0; i < 3 && st.ok(); ++i) st = c->ReceiveFor(buf, sizeof(buf), &n, 3000);
        SG_EXPECT(st == SG_CLOSED || st == SG_NETWORK_ERROR);
    }
}
