#pragma once
/**
 * @file
 * @brief Time sources.
 *
 * Expiry and timeouts use the monotonic clock so wall-clock changes cannot extend or shorten sessions; absolute
 * timestamps (licenses, tokens) use Unix epoch milliseconds from the system clock.
 */

#include <chrono>
#include <cstdint>

namespace sg {

/**
 * @brief Returns milliseconds on the monotonic clock (std::chrono::steady_clock).
 *
 * The epoch is unspecified; only differences between two values are meaningful.
 *
 * @return Monotonic time in milliseconds.
 */
inline uint64_t MonotonicMs() noexcept
{
    using namespace std::chrono;
    return static_cast<uint64_t>(duration_cast<milliseconds>(steady_clock::now().time_since_epoch()).count());
}

/**
 * @brief Returns the wall-clock time (std::chrono::system_clock) as Unix epoch milliseconds.
 * @return Milliseconds since 1970-01-01 UTC; 0 when the system clock is set before the epoch.
 */
inline uint64_t UnixTimeMs() noexcept
{
    using namespace std::chrono;
    const auto ms = duration_cast<milliseconds>(system_clock::now().time_since_epoch()).count();
    return ms < 0 ? 0 : static_cast<uint64_t>(ms);
}

/**
 * @brief Milliseconds elapsed from @p since to @p now, saturating at 0.
 *
 * Timestamps taken on different threads may be observed out of order; plain unsigned subtraction would then wrap
 * to ~2^64 and trigger every timeout at once.
 *
 * @param[in] now   Later timestamp (ms).
 * @param[in] since Earlier timestamp (ms), from the same clock.
 * @return `now - since`, or 0 when @p since is not before @p now.
 */
constexpr uint64_t ElapsedMs(uint64_t now, uint64_t since) noexcept { return now > since ? now - since : 0; }

/**
 * @brief Deadline helper for blocking operations; timeout 0 means "no deadline".
 *
 * The expiry is fixed at construction on the monotonic clock (MonotonicMs()).
 *
 * @note Immutable after construction: the const methods may be called from any thread.
 */
class Deadline {
public:
    /**
     * @brief Starts a deadline @p timeout_ms from now.
     * @param[in] timeout_ms Timeout in milliseconds; 0 means no deadline (infinite).
     */
    explicit Deadline(uint32_t timeout_ms) noexcept
        : infinite_(timeout_ms == 0), expires_at_(MonotonicMs() + timeout_ms) {}

    /** @brief Returns a deadline that never expires. @return Same as `Deadline(0)`. */
    static Deadline Infinite() noexcept { return Deadline(0); }

    /** @brief Returns whether the deadline has no expiry. @return true when constructed with timeout 0. */
    bool infinite() const noexcept { return infinite_; }
    /**
     * @brief Returns whether the deadline has passed.
     * @return true when the deadline is finite and the monotonic clock has reached its expiry.
     */
    bool Expired() const noexcept { return !infinite_ && MonotonicMs() >= expires_at_; }

    /**
     * @brief Remaining milliseconds, clamped to @p max_slice (used to poll in bounded slices).
     * @param[in] max_slice Upper bound for the result (ms).
     * @return @p max_slice for an infinite deadline; 0 once expired; otherwise the smaller of the time left and
     *         @p max_slice.
     */
    uint32_t RemainingMs(uint32_t max_slice) const noexcept
    {
        if (infinite_) return max_slice;
        const uint64_t now = MonotonicMs();
        if (now >= expires_at_) return 0;
        const uint64_t left = expires_at_ - now;
        return left < max_slice ? static_cast<uint32_t>(left) : max_slice;
    }

private:
    bool infinite_;        ///< True when constructed with timeout 0.
    uint64_t expires_at_;  ///< Expiry on the MonotonicMs() clock; unused when infinite_.
};

}  // namespace sg
