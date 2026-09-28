// Byte containers and views.
//  - Bytes:        ordinary byte vector.
//  - SecureBytes:  vector whose storage is wiped on every deallocation
//                  (including reallocation), used for keys and secrets.
//  - ByteView:     non-owning read-only view (C++17 has no std::span).
#pragma once

#include <array>
#include <cstddef>
#include <cstdint>
#include <limits>
#include <new>
#include <string>
#include <vector>

namespace sg {

// Overwrites memory in a way the optimiser cannot elide.
void SecureZero(void* data, size_t size) noexcept;

// Constant-time comparison. Returns false when the sizes differ (size is not secret).
bool ConstantTimeEqual(const void* a, size_t a_size, const void* b, size_t b_size) noexcept;

template <class T>
struct ZeroingAllocator {
    using value_type = T;

    ZeroingAllocator() noexcept = default;
    template <class U>
    ZeroingAllocator(const ZeroingAllocator<U>&) noexcept {}  // NOLINT(google-explicit-constructor)

    T* allocate(size_t n)
    {
        if (n > std::numeric_limits<size_t>::max() / sizeof(T)) throw std::bad_alloc();
        return static_cast<T*>(::operator new(n * sizeof(T)));
    }

    void deallocate(T* p, size_t n) noexcept
    {
        SecureZero(p, n * sizeof(T));
        ::operator delete(p);
    }

    template <class U>
    bool operator==(const ZeroingAllocator<U>&) const noexcept { return true; }
    template <class U>
    bool operator!=(const ZeroingAllocator<U>&) const noexcept { return false; }
};

using Bytes = std::vector<uint8_t>;
using SecureBytes = std::vector<uint8_t, ZeroingAllocator<uint8_t>>;

class ByteView {
public:
    constexpr ByteView() noexcept = default;
    constexpr ByteView(const uint8_t* data, size_t size) noexcept : data_(data), size_(size) {}
    ByteView(const Bytes& bytes) noexcept : data_(bytes.data()), size_(bytes.size()) {}  // NOLINT
    ByteView(const SecureBytes& bytes) noexcept : data_(bytes.data()), size_(bytes.size()) {}  // NOLINT
    template <size_t N>
    constexpr ByteView(const std::array<uint8_t, N>& a) noexcept : data_(a.data()), size_(N) {}  // NOLINT

    constexpr const uint8_t* data() const noexcept { return data_; }
    constexpr size_t size() const noexcept { return size_; }
    constexpr bool empty() const noexcept { return size_ == 0; }
    constexpr const uint8_t* begin() const noexcept { return data_; }
    constexpr const uint8_t* end() const noexcept { return data_ + size_; }
    const uint8_t& operator[](size_t i) const noexcept { return data_[i]; }

    // Returns an empty view when the requested range is out of bounds.
    ByteView Sub(size_t offset, size_t length) const noexcept
    {
        if (offset > size_ || length > size_ - offset) return ByteView();
        return ByteView(data_ + offset, length);
    }

    Bytes ToBytes() const { return Bytes(data_, data_ + size_); }

private:
    const uint8_t* data_ = nullptr;
    size_t size_ = 0;
};

inline void Append(Bytes& out, ByteView v) { out.insert(out.end(), v.begin(), v.end()); }
inline void Append(SecureBytes& out, ByteView v) { out.insert(out.end(), v.begin(), v.end()); }

std::string ToHex(ByteView bytes);
// Short, log-friendly identifier prefix (first 8 bytes hex). Only for non-secret identifiers.
std::string ShortId(ByteView bytes);

}  // namespace sg
