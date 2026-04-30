#pragma once

#include <cstdint>
#include <span>
#include <vector>

namespace nit::crypto::osnova {

/**
 * @brief HMAC using SHA-256 Protocol (RFC 2104).
 */
class HmacSha256 {
public:
    static constexpr size_t DIGEST_SIZE = 32;
    static constexpr size_t BLOCK_SIZE = 64;

    HmacSha256() noexcept = default;

    /**
     * @brief Computes HMAC-SHA256.
     */
    static void compute(
        std::span<uint8_t, DIGEST_SIZE> mac,
        std::span<const uint8_t> key,
        std::span<const uint8_t> message) noexcept;
};

} // namespace nit::crypto::osnova
