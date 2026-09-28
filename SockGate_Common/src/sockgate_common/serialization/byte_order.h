#pragma once
/**
 * @file
 * @brief Big-endian (network byte order) load/store helpers.
 *
 * The SockGate wire format is big-endian throughout and this file is the only place where the byte order is
 * spelled out.
 *
 * @warning The helpers do no bounds checking: @p p must point to at least 2, 4 or 8 accessible bytes. Use
 *          sg::ser::Reader for untrusted input.
 */

#include <cstdint>

namespace sg::ser {

/**
 * @brief Loads a big-endian 16-bit value.
 * @param[in] p At least 2 readable bytes.
 * @return The value.
 */
constexpr uint16_t LoadBE16(const uint8_t* p) noexcept
{
    return static_cast<uint16_t>((static_cast<uint16_t>(p[0]) << 8) | p[1]);
}

/**
 * @brief Loads a big-endian 32-bit value.
 * @param[in] p At least 4 readable bytes.
 * @return The value.
 */
constexpr uint32_t LoadBE32(const uint8_t* p) noexcept
{
    return (static_cast<uint32_t>(p[0]) << 24) | (static_cast<uint32_t>(p[1]) << 16) |
           (static_cast<uint32_t>(p[2]) << 8) | static_cast<uint32_t>(p[3]);
}

/**
 * @brief Loads a big-endian 64-bit value.
 * @param[in] p At least 8 readable bytes.
 * @return The value.
 */
constexpr uint64_t LoadBE64(const uint8_t* p) noexcept
{
    return (static_cast<uint64_t>(LoadBE32(p)) << 32) | LoadBE32(p + 4);
}

/**
 * @brief Stores a 16-bit value big-endian.
 * @param[out] p At least 2 writable bytes.
 * @param[in]  v Value.
 */
inline void StoreBE16(uint8_t* p, uint16_t v) noexcept
{
    p[0] = static_cast<uint8_t>(v >> 8);
    p[1] = static_cast<uint8_t>(v);
}

/**
 * @brief Stores a 32-bit value big-endian.
 * @param[out] p At least 4 writable bytes.
 * @param[in]  v Value.
 */
inline void StoreBE32(uint8_t* p, uint32_t v) noexcept
{
    p[0] = static_cast<uint8_t>(v >> 24);
    p[1] = static_cast<uint8_t>(v >> 16);
    p[2] = static_cast<uint8_t>(v >> 8);
    p[3] = static_cast<uint8_t>(v);
}

/**
 * @brief Stores a 64-bit value big-endian.
 * @param[out] p At least 8 writable bytes.
 * @param[in]  v Value.
 */
inline void StoreBE64(uint8_t* p, uint64_t v) noexcept
{
    StoreBE32(p, static_cast<uint32_t>(v >> 32));
    StoreBE32(p + 4, static_cast<uint32_t>(v));
}

}  // namespace sg::ser
