#include "tls/tls_channel.h"

#include "sockgate_common/core/clock.h"

namespace sg::client {
namespace {

constexpr size_t kReceiveChunk = 16 * 1024;

}  // namespace

TlsChannel::TlsChannel(std::shared_ptr<net::ITransport> transport, std::unique_ptr<tls::ITlsEngine> engine)
    : transport_(std::move(transport)), engine_(std::move(engine))
{
}

TlsChannel::~TlsChannel()
{
    if (transport_) transport_->Close();
}

void TlsChannel::CollectOutgoingLocked()
{
    if (engine_->PendingOutgoing() == 0) return;
    Bytes chunk;
    engine_->TakeOutgoing(&chunk);
    if (!chunk.empty()) outbound_.push_back(std::move(chunk));
}

Status TlsChannel::Flush(bool use_timeout, uint32_t timeout_ms)
{
    std::lock_guard<std::mutex> io(send_io_mutex_);
    for (;;) {
        Bytes chunk;
        {
            std::lock_guard<std::mutex> lock(tls_mutex_);
            if (outbound_.empty()) return OkStatus();
            chunk = std::move(outbound_.front());
            outbound_.pop_front();
        }
        SG_TRY(use_timeout ? transport_->SendFor(chunk.data(), chunk.size(), timeout_ms)
                           : transport_->Send(chunk.data(), chunk.size()));
    }
}

Status TlsChannel::Handshake(uint32_t timeout_ms)
{
    const Deadline deadline(timeout_ms);
    std::vector<uint8_t> buffer(kReceiveChunk);
    for (;;) {
        Status st;
        {
            std::lock_guard<std::mutex> lock(tls_mutex_);
            st = engine_->Handshake();
            CollectOutgoingLocked();  // also flushes alerts produced on failure
        }
        const Status flushed = Flush();
        if (st.ok()) return flushed;
        if (st != kStatusWouldBlock) return st;
        SG_TRY(flushed);

        if (deadline.Expired()) return SG_TIMEOUT;
        const uint32_t wait = deadline.infinite() ? net::kNoTimeout : std::max<uint32_t>(1, deadline.RemainingMs(UINT32_MAX));
        size_t n = 0;
        const Status rst = transport_->ReceiveFor(buffer.data(), buffer.size(), &n, wait);
        if (rst == SG_CLOSED) return SG_TLS_ERROR;  // peer went away mid-handshake
        SG_TRY(rst);
        std::lock_guard<std::mutex> lock(tls_mutex_);
        SG_TRY(engine_->FeedIncoming(ByteView(buffer.data(), n)));
    }
}

Status TlsChannel::Send(const uint8_t* data, size_t size)
{
    if (data == nullptr && size != 0) return SG_INVALID_ARGUMENT;
    {
        std::lock_guard<std::mutex> lock(tls_mutex_);
        SG_TRY(engine_->Write(ByteView(data, size)));
        CollectOutgoingLocked();
    }
    return Flush();
}

Status TlsChannel::SendFor(const uint8_t* data, size_t size, uint32_t timeout_ms)
{
    if (data == nullptr && size != 0) return SG_INVALID_ARGUMENT;
    {
        std::lock_guard<std::mutex> lock(tls_mutex_);
        SG_TRY(engine_->Write(ByteView(data, size)));
        CollectOutgoingLocked();
    }
    return Flush(true, timeout_ms == 0 ? 1 : timeout_ms);
}

Status TlsChannel::Receive(uint8_t* buffer, size_t capacity, size_t* received, uint32_t timeout_ms)
{
    if (buffer == nullptr || capacity == 0 || received == nullptr) return SG_INVALID_ARGUMENT;
    *received = 0;
    std::lock_guard<std::mutex> serial(receive_io_mutex_);
    const Deadline deadline(timeout_ms);
    std::vector<uint8_t> chunk(kReceiveChunk);
    for (;;) {
        Status st;
        bool have_output;
        {
            std::lock_guard<std::mutex> lock(tls_mutex_);
            st = engine_->Read(buffer, capacity, received);
            CollectOutgoingLocked();  // e.g. KeyUpdate responses generated while reading
            have_output = !outbound_.empty();
        }
        if (have_output) SG_TRY(Flush());
        if (st.ok()) return OkStatus();
        if (st != kStatusWouldBlock) return st;

        if (deadline.Expired()) return SG_TIMEOUT;
        const uint32_t wait = deadline.infinite() ? net::kNoTimeout : std::max<uint32_t>(1, deadline.RemainingMs(UINT32_MAX));
        size_t n = 0;
        SG_TRY(transport_->ReceiveFor(chunk.data(), chunk.size(), &n, wait));
        std::lock_guard<std::mutex> lock(tls_mutex_);
        SG_TRY(engine_->FeedIncoming(ByteView(chunk.data(), n)));
    }
}

Status TlsChannel::ChannelBinding(crypto::Sha256Digest* out)
{
    std::lock_guard<std::mutex> lock(tls_mutex_);
    return engine_->ChannelBinding(out);
}

Status TlsChannel::ExportKeyingMaterial(const std::string& label, ByteView context, uint8_t* out, size_t size)
{
    std::lock_guard<std::mutex> lock(tls_mutex_);
    return engine_->ExportKeyingMaterial(label, context, true, out, size);
}

Status TlsChannel::RequestKeyUpdate()
{
    {
        std::lock_guard<std::mutex> lock(tls_mutex_);
        SG_TRY(engine_->RequestKeyUpdate());
        CollectOutgoingLocked();
    }
    return Flush();
}

tls::TlsSessionInfo TlsChannel::SessionInfo()
{
    std::lock_guard<std::mutex> lock(tls_mutex_);
    return engine_->SessionInfo();
}

std::string TlsChannel::ErrorDetail()
{
    std::lock_guard<std::mutex> lock(tls_mutex_);
    return engine_->ErrorDetail();
}

std::string TlsChannel::PeerAddress() const { return transport_->PeerAddress(); }

void TlsChannel::Shutdown(uint32_t timeout_ms) noexcept
{
    {
        std::lock_guard<std::mutex> lock(tls_mutex_);
        if (engine_->IsHandshakeComplete() && engine_->Shutdown().ok()) CollectOutgoingLocked();
    }
    // Only send close_notify if no other thread is mid-send; never block here.
    std::unique_lock<std::mutex> io(send_io_mutex_, std::try_to_lock);
    if (io.owns_lock()) {
        for (;;) {
            Bytes chunk;
            {
                std::lock_guard<std::mutex> lock(tls_mutex_);
                if (outbound_.empty()) break;
                chunk = std::move(outbound_.front());
                outbound_.pop_front();
            }
            if (!transport_->SendFor(chunk.data(), chunk.size(), timeout_ms == 0 ? 1 : timeout_ms).ok()) break;
        }
    }
    transport_->Shutdown();
}

void TlsChannel::Abort() noexcept { transport_->Shutdown(); }

}  // namespace sg::client
