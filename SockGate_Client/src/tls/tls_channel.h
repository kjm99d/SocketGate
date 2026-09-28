#pragma once
/**
 * @file
 * @brief Blocking TLS channel for the client: drives an ITlsEngine over an ITransport.
 *
 * Concurrency: Send() and Receive() may run concurrently on different threads. All engine calls happen under
 * tls_mutex_; ciphertext produced under that lock is appended to an outbound queue and flushed under
 * send_io_mutex_, so TLS records reach the wire in exactly the order the engine produced them even when Receive()
 * must emit records (e.g. a TLS 1.3 KeyUpdate response). Network I/O never happens while tls_mutex_ is held.
 */

#include "sockgate_common/net/transport.h"
#include "sockgate_common/tls/tls.h"

#include <deque>
#include <memory>
#include <mutex>

namespace sg::client {

/**
 * @brief Blocking TLS connection over a connected transport.
 *
 * @note Thread safety: Send() / SendFor() and Receive() may run concurrently; concurrent Receive() calls are
 *       serialised by receive_io_mutex_. Shutdown() and Abort() may be called from any thread. Locks are taken in
 *       the order receive_io_mutex_, send_io_mutex_, tls_mutex_.
 */
class TlsChannel {
public:
    /**
     * @brief Wraps a connected transport; no I/O happens until Handshake().
     * @param[in] transport Connected byte transport (shared; closed by the destructor).
     * @param[in] engine    Client TLS engine for this connection (owned).
     */
    TlsChannel(std::shared_ptr<net::ITransport> transport, std::unique_ptr<tls::ITlsEngine> engine);
    /** @brief Closes the transport (which waits for its operations in flight to leave). */
    ~TlsChannel();

    TlsChannel(const TlsChannel&) = delete;
    TlsChannel& operator=(const TlsChannel&) = delete;

    /**
     * @brief Runs the TLS handshake (including certificate, hostname and pin checks).
     *
     * Records the engine produces, including alerts on failure, are flushed before returning. @p timeout_ms bounds
     * waiting for the server; records are written with the transport's I/O timeout. Other transport errors are
     * passed through.
     *
     * @param[in] timeout_ms Budget for the whole handshake (ms); 0 = no limit.
     * @retval SG_OK                Handshake complete.
     * @retval SG_TIMEOUT           The budget ran out.
     * @retval SG_CERTIFICATE_ERROR Chain, validity or host name verification failed.
     * @retval SG_PINNING_ERROR     The verified chain matches no SPKI pin.
     * @retval SG_TLS_ERROR         Other TLS failure, including end-of-stream mid-handshake (also after Abort()).
     * @retval SG_CLOSED            A write failed because the transport was shut down (e.g. by Abort()).
     */
    Status Handshake(uint32_t timeout_ms);

    /**
     * @brief Encrypts and sends all bytes (transport I/O timeout).
     *
     * Also writes any records queued earlier, in order. Engine and other transport errors are passed through.
     *
     * @param[in] data Plaintext; may be nullptr only when @p size is 0.
     * @param[in] size Number of bytes.
     * @retval SG_OK               All bytes handed to the transport.
     * @retval SG_INVALID_ARGUMENT @p data is nullptr with a non-zero @p size.
     * @retval SG_TIMEOUT          The transport I/O timeout elapsed.
     * @retval SG_CLOSED           The transport was shut down.
     */
    Status Send(const uint8_t* data, size_t size);
    /**
     * @brief As Send with an explicit bound on the network write.
     *
     * @param[in] data       Plaintext; may be nullptr only when @p size is 0.
     * @param[in] size       Number of bytes.
     * @param[in] timeout_ms Bound for the write of each queued record chunk (ms); 0 is treated as 1 ms, never as
     *                       "no limit".
     * @return As Send().
     */
    Status SendFor(const uint8_t* data, size_t size, uint32_t timeout_ms);

    /**
     * @brief Receives decrypted bytes (at least one). kNoTimeout waits indefinitely.
     *
     * SG_CLOSED after close_notify or end-of-stream, SG_TIMEOUT on deadline. Records the engine emits while reading
     * (e.g. a KeyUpdate response) are flushed before returning. Engine and other transport errors are passed
     * through.
     *
     * @param[out] buffer     Destination; must not be nullptr.
     * @param[in]  capacity   Size of @p buffer; must not be 0.
     * @param[out] received   Receives the number of bytes stored (0 on failure).
     * @param[in]  timeout_ms Deadline (ms); net::kNoTimeout (0) waits indefinitely.
     * @retval SG_OK               At least one byte received.
     * @retval SG_CLOSED           close_notify or end-of-stream, or the transport was shut down.
     * @retval SG_TIMEOUT          The deadline passed.
     * @retval SG_INVALID_ARGUMENT A nullptr argument or @p capacity 0.
     */
    Status Receive(uint8_t* buffer, size_t capacity, size_t* received, uint32_t timeout_ms);

    /**
     * @brief RFC 9266 tls-exporter channel binding of this connection (32 bytes).
     * @param[out] out Receives the channel binding.
     * @return The engine's status.
     */
    Status ChannelBinding(crypto::Sha256Digest* out);
    /**
     * @brief RFC 5705 / RFC 8446 keying material exporter, with a context value.
     * @param[in]  label   Exporter label.
     * @param[in]  context Exporter context.
     * @param[out] out     Receives @p size bytes.
     * @param[in]  size    Number of bytes to export.
     * @return The engine's status.
     * @warning The output is secret key material: wipe it after use.
     */
    Status ExportKeyingMaterial(const std::string& label, ByteView context, uint8_t* out, size_t size);
    /**
     * @brief Requests a TLS 1.3 KeyUpdate (update_requested) and writes it; no-op success on TLS 1.2.
     * @return The engine's or the transport's status.
     */
    Status RequestKeyUpdate();
    /**
     * @brief Negotiated TLS parameters.
     * @return Protocol, cipher, whether TLS 1.3 and whether Extended Master Secret is in use.
     */
    tls::TlsSessionInfo SessionInfo();
    /**
     * @brief Reason for the last TLS failure.
     * @return Human-readable text for logs; contains no secrets.
     */
    std::string ErrorDetail();
    /**
     * @brief Address of the transport's peer.
     * @return "1.2.3.4:443" or "[::1]:443"; with a proxy, the address of the proxy.
     */
    std::string PeerAddress() const;

    /**
     * @brief Best-effort close_notify (bounded by timeout_ms, skipped if another thread is mid-send), then transport
     *        shutdown. Thread-safe.
     *
     * close_notify is only sent after a completed handshake; each record write is bounded by @p timeout_ms (0 is
     * treated as 1 ms). The transport is shut down, not released (the destructor closes it).
     *
     * @param[in] timeout_ms Bound for the close_notify write (ms).
     */
    void Shutdown(uint32_t timeout_ms = 200) noexcept;
    /** @brief Wakes blocked operations without sending anything. Thread-safe. */
    void Abort() noexcept;

private:
    /**
     * @brief Writes the queued ciphertext in order under send_io_mutex_ (outside tls_mutex_).
     * @param[in] use_timeout false: transport I/O timeout; true: @p timeout_ms per chunk.
     * @param[in] timeout_ms  Bound per chunk when @p use_timeout (ms).
     * @return OK once the queue is empty; the first transport error otherwise.
     */
    Status Flush(bool use_timeout = false, uint32_t timeout_ms = 0);
    /** @brief Moves the engine's pending ciphertext to outbound_. Caller holds tls_mutex_. */
    void CollectOutgoingLocked();

    std::shared_ptr<net::ITransport> transport_;  ///< Underlying byte transport.
    std::mutex tls_mutex_;                          ///< Guards engine_ and outbound_; never held during network I/O.
    std::unique_ptr<tls::ITlsEngine> engine_;       ///< TLS engine (not thread-safe); guarded by tls_mutex_.
    std::deque<Bytes> outbound_;                    ///< Ciphertext to write, in engine order; guarded by tls_mutex_.
    std::mutex send_io_mutex_;                      ///< Serialises network writes (queue order == wire order).
    std::mutex receive_io_mutex_;                   ///< Serialises Receive() calls.
};

}  // namespace sg::client
