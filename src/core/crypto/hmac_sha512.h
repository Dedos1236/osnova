#pragma once

#include <cstdint>
#include <span>
#include <vector>

namespace nit::crypto::osnova {

/**
 * @brief HMAC-SHA512 implementation.
 */
class HmacSha512 {
public:
    static constexpr size_t MAC_SIZE = 64;

    static void compute(
        std::span<uint8_t, MAC_SIZE> mac_out,
        std::span<const uint8_t> key,
        std::span<const uint8_t> data) noexcept;
};

} // namespace nit::crypto::osnova
