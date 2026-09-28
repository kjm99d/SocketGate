// Time sources. Expiry and timeouts use the monotonic clock so wall-clock
// changes cannot extend or shorten sessions; absolute timestamps (licenses,
// tokens) use Unix epoch milliseconds from the system clock.
#pragma once

#include <chrono>
#include <cstdint>

namespace sg {

inline uint64_t MonotonicMs() noexcept
{
    using namespace std::chrono;
    return static_cast<uint64_t>(duration_cast<milliseconds>(steady_clock::now().time_since_epoch()).count());
}

inline uint64_t UnixTimeMs() noexcept
{
    using namespace std::chrono;
    const auto ms = duration_cast<milliseconds>(system_clock::now().time_since_epoch()).count();
    return ms < 0 ? 0 : static_cast<uint64_t>(ms);
}

// Deadline helper for blocking operations; timeout 0 means "no deadline".
class Deadline {
public:
    explicit Deadline(uint32_t timeout_ms) noexcept
        : infinite_(timeout_ms == 0), expires_at_(MonotonicMs() + timeout_ms) {}

    static Deadline Infinite() noexcept { return Deadline(0); }

    bool infinite() const noexcept { return infinite_; }
    bool Expired() const noexcept { return !infinite_ && MonotonicMs() >= expires_at_; }

    // Remaining milliseconds, clamped to max_slice (used to poll in bounded slices).
    uint32_t RemainingMs(uint32_t max_slice) const noexcept
    {
        if (infinite_) return max_slice;
        const uint64_t now = MonotonicMs();
        if (now >= expires_at_) return 0;
        const uint64_t left = expires_at_ - now;
        return left < max_slice ? static_cast<uint32_t>(left) : max_slice;
    }

private:
    bool infinite_;
    uint64_t expires_at_;
};

}  // namespace sg
