// Blocking TLS channel for the client: drives an ITlsEngine over an ITransport.
//
// Concurrency: Send() and Receive() may run concurrently on different threads.
// All engine calls happen under tls_mutex_; ciphertext produced under that
// lock is appended to an outbound queue and flushed under send_io_mutex_, so
// TLS records reach the wire in exactly the order the engine produced them
// even when Receive() must emit records (e.g. a TLS 1.3 KeyUpdate response).
// Network I/O never happens while tls_mutex_ is held.
#pragma once

#include "sockgate_common/net/transport.h"
#include "sockgate_common/tls/tls.h"

#include <deque>
#include <memory>
#include <mutex>

namespace sg::client {

class TlsChannel {
public:
    TlsChannel(std::shared_ptr<net::ITransport> transport, std::unique_ptr<tls::ITlsEngine> engine);
    ~TlsChannel();

    TlsChannel(const TlsChannel&) = delete;
    TlsChannel& operator=(const TlsChannel&) = delete;

    // Runs the TLS handshake (including certificate, hostname and pin checks).
    Status Handshake(uint32_t timeout_ms);

    // Encrypts and sends all bytes (transport I/O timeout).
    Status Send(const uint8_t* data, size_t size);
    // As Send with an explicit bound on the network write.
    Status SendFor(const uint8_t* data, size_t size, uint32_t timeout_ms);

    // Receives decrypted bytes (at least one). kNoTimeout waits indefinitely.
    // SG_CLOSED after close_notify or end-of-stream, SG_TIMEOUT on deadline.
    Status Receive(uint8_t* buffer, size_t capacity, size_t* received, uint32_t timeout_ms);

    Status ChannelBinding(crypto::Sha256Digest* out);
    Status ExportKeyingMaterial(const std::string& label, ByteView context, uint8_t* out, size_t size);
    Status RequestKeyUpdate();
    tls::TlsSessionInfo SessionInfo();
    std::string ErrorDetail();
    std::string PeerAddress() const;

    // Best-effort close_notify (bounded by timeout_ms, skipped if another
    // thread is mid-send), then transport shutdown. Thread-safe.
    void Shutdown(uint32_t timeout_ms = 200) noexcept;
    // Wakes blocked operations without sending anything. Thread-safe.
    void Abort() noexcept;

private:
    Status Flush(bool use_timeout = false, uint32_t timeout_ms = 0);
    void CollectOutgoingLocked();

    std::shared_ptr<net::ITransport> transport_;
    std::mutex tls_mutex_;
    std::unique_ptr<tls::ITlsEngine> engine_;       // guarded by tls_mutex_
    std::deque<Bytes> outbound_;                    // guarded by tls_mutex_
    std::mutex send_io_mutex_;
    std::mutex receive_io_mutex_;
};

}  // namespace sg::client
