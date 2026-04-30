#pragma once

#include <cstdint>
#include <span>

namespace nit::crypto::osnova {

/**
 * @brief PBKDF2 using HMAC-SHA256.
 * RFC 2898.
 */
class Pbkdf2HmacSha256 {
public:
    /**
     * @brief Derive key using PBKDF2-HMAC-SHA256.
     * 
     * @param out Output buffer for derived key
     * @param password Password
     * @param salt Salt
     * @param iterations Number of iterations
     */
    static void derive_key(
        std::span<uint8_t> out,
        std::span<const uint8_t> password,
        std::span<const uint8_t> salt,
        uint32_t iterations) noexcept;
};

} // namespace nit::crypto::osnova
