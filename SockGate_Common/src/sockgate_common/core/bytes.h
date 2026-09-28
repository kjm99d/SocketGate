#pragma once
/**
 * @file
 * @brief Byte containers and views.
 *
 * - sg::Bytes: ordinary byte vector.
 * - sg::SecureBytes: vector whose storage is wiped on every deallocation (including reallocation), used for keys
 *   and secrets.
 * - sg::ByteView: non-owning read-only view (C++17 has no std::span).
 */

#include <array>
#include <cstddef>
#include <cstdint>
#include <limits>
#include <new>
#include <string>
#include <vector>

namespace sg {

/**
 * @brief Overwrites memory in a way the optimiser cannot elide.
 *
 * Implemented with OPENSSL_cleanse(). Does nothing when @p data is null or @p size is 0.
 *
 * @param[out] data Memory to wipe (may be null).
 * @param[in]  size Number of bytes to set to zero.
 */
void SecureZero(void* data, size_t size) noexcept;

/**
 * @brief Constant-time comparison of two byte ranges.
 *
 * The running time depends only on the size, not on the contents (CRYPTO_memcmp()). The sizes themselves are
 * compared first and are not treated as secret.
 *
 * @param[in] a      First range (may be null when @p a_size is 0).
 * @param[in] a_size Size of @p a in bytes.
 * @param[in] b      Second range (may be null when @p b_size is 0).
 * @param[in] b_size Size of @p b in bytes.
 * @return true when both ranges have the same size and contents (two empty ranges are equal); false when the
 *         sizes differ or any byte differs.
 */
bool ConstantTimeEqual(const void* a, size_t a_size, const void* b, size_t b_size) noexcept;

/**
 * @brief Standard allocator that wipes storage with SecureZero() before releasing it.
 *
 * Every deallocation, including the one of the old buffer when a vector reallocates, first overwrites the whole
 * allocated block. All instances are interchangeable (stateless).
 *
 * @warning Only deallocation wipes: elements removed from a container without releasing its storage (clear(),
 *          resize() to a smaller size, pop_back()) stay in memory until the storage is deallocated.
 * @tparam T Element type.
 */
template <class T>
struct ZeroingAllocator {
    using value_type = T;  ///< Element type (allocator requirement).

    /** @brief Creates an allocator. */
    ZeroingAllocator() noexcept = default;
    /** @brief Rebinding copy from an allocator of another element type (stateless, so nothing is copied). */
    template <class U>
    ZeroingAllocator(const ZeroingAllocator<U>&) noexcept {}  // NOLINT(google-explicit-constructor)

    /**
     * @brief Allocates uninitialised storage for @p n elements with ::operator new.
     * @param[in] n Number of elements.
     * @return Pointer to the storage.
     * @throws std::bad_alloc when @p n * sizeof(T) overflows size_t or the allocation fails.
     */
    T* allocate(size_t n)
    {
        if (n > std::numeric_limits<size_t>::max() / sizeof(T)) throw std::bad_alloc();
        return static_cast<T*>(::operator new(n * sizeof(T)));
    }

    /**
     * @brief Wipes @p n elements' worth of storage with SecureZero(), then releases it.
     * @param[in] p Storage returned by allocate().
     * @param[in] n Element count passed to allocate().
     */
    void deallocate(T* p, size_t n) noexcept
    {
        SecureZero(p, n * sizeof(T));
        ::operator delete(p);
    }

    /** @brief Always true: every ZeroingAllocator can release memory from any other. @return true */
    template <class U>
    bool operator==(const ZeroingAllocator<U>&) const noexcept { return true; }
    /** @brief Always false (see operator==). @return false */
    template <class U>
    bool operator!=(const ZeroingAllocator<U>&) const noexcept { return false; }
};

/** @brief Ordinary byte vector; its storage is not wiped on release. */
using Bytes = std::vector<uint8_t>;
/**
 * @brief Byte vector whose storage is wiped on every deallocation (including reallocation); used for keys and
 *        secrets.
 * @see ZeroingAllocator
 */
using SecureBytes = std::vector<uint8_t, ZeroingAllocator<uint8_t>>;

/**
 * @brief Non-owning, read-only view of a contiguous byte range (C++17 has no std::span).
 *
 * The viewed memory must outlive the view and must not be reallocated while the view is used (e.g. a Bytes that
 * grows invalidates views of it). A default-constructed view is empty with a null data pointer.
 *
 * @note A view is a trivially copyable value; it holds no lock and adds no synchronisation to the viewed memory.
 */
class ByteView {
public:
    /** @brief Creates an empty view (null data, size 0). */
    constexpr ByteView() noexcept = default;
    /**
     * @brief Views @p size bytes starting at @p data.
     * @param[in] data First byte (not copied).
     * @param[in] size Number of bytes.
     */
    constexpr ByteView(const uint8_t* data, size_t size) noexcept : data_(data), size_(size) {}
    /** @brief Views the current contents of @p bytes (implicit). @param[in] bytes Vector to view. */
    ByteView(const Bytes& bytes) noexcept : data_(bytes.data()), size_(bytes.size()) {}  // NOLINT
    /** @brief Views the current contents of @p bytes (implicit). @param[in] bytes Vector to view. */
    ByteView(const SecureBytes& bytes) noexcept : data_(bytes.data()), size_(bytes.size()) {}  // NOLINT
    /** @brief Views a fixed-size array (implicit). @tparam N Array size. @param[in] a Array to view. */
    template <size_t N>
    constexpr ByteView(const std::array<uint8_t, N>& a) noexcept : data_(a.data()), size_(N) {}  // NOLINT

    /** @brief Returns the first byte of the range. @return Data pointer (null for a default-constructed view). */
    constexpr const uint8_t* data() const noexcept { return data_; }
    /** @brief Returns the number of bytes in the view. @return Size in bytes. */
    constexpr size_t size() const noexcept { return size_; }
    /** @brief Returns whether the view has no bytes. @return true when size() is 0. */
    constexpr bool empty() const noexcept { return size_ == 0; }
    /** @brief Returns an iterator to the first byte. @return Same as data(). */
    constexpr const uint8_t* begin() const noexcept { return data_; }
    /** @brief Returns an iterator one past the last byte. @return data() + size(). */
    constexpr const uint8_t* end() const noexcept { return data_ + size_; }
    /**
     * @brief Returns the byte at index @p i.
     * @warning Not bounds-checked: @p i must be less than size().
     * @param[in] i Index.
     * @return Reference to the byte.
     */
    const uint8_t& operator[](size_t i) const noexcept { return data_[i]; }

    /**
     * @brief Returns the sub-range of @p length bytes starting at @p offset.
     *
     * The bounds check cannot overflow.
     *
     * @param[in] offset Start of the sub-range, relative to data().
     * @param[in] length Number of bytes.
     * @return The sub-range, or an empty view when the requested range is out of bounds.
     */
    ByteView Sub(size_t offset, size_t length) const noexcept
    {
        if (offset > size_ || length > size_ - offset) return ByteView();
        return ByteView(data_ + offset, length);
    }

    /**
     * @brief Copies the viewed bytes into a new ordinary vector.
     * @warning The copy is a Bytes and is not wiped when released.
     * @return The copy.
     */
    Bytes ToBytes() const { return Bytes(data_, data_ + size_); }

private:
    const uint8_t* data_ = nullptr;  ///< First viewed byte; not owned.
    size_t size_ = 0;                ///< Number of viewed bytes.
};

/**
 * @brief Appends the bytes of @p v to @p out.
 * @param[in,out] out Vector to append to.
 * @param[in]     v   Bytes to append.
 */
inline void Append(Bytes& out, ByteView v) { out.insert(out.end(), v.begin(), v.end()); }
/**
 * @brief Appends the bytes of @p v to @p out; storage released by a reallocation is wiped.
 * @param[in,out] out Vector to append to.
 * @param[in]     v   Bytes to append.
 */
inline void Append(SecureBytes& out, ByteView v) { out.insert(out.end(), v.begin(), v.end()); }

/**
 * @brief Formats bytes as lowercase hexadecimal, two digits per byte.
 * @param[in] bytes Bytes to format.
 * @return The hex string (empty for an empty view).
 */
std::string ToHex(ByteView bytes);
/**
 * @brief Short, log-friendly identifier prefix: the first 8 bytes in hex (fewer when @p bytes is shorter).
 * @warning Only for non-secret identifiers.
 * @param[in] bytes Identifier.
 * @return Up to 16 lowercase hex digits.
 */
std::string ShortId(ByteView bytes);

}  // namespace sg
