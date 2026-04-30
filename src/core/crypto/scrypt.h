#pragma once

#include <cstdint>
#include <span>

namespace nit::crypto::osnova {

/**
 * @brief scrypt Key Derivation Function.
 * RFC 7914.
 */
class Scrypt {
public:
    /**
     * @brief Derive key using scrypt.
     * 
     * @param out Output buffer for derived key
     * @param password Password
     * @param salt Salt
     * @param N CPU/Memory cost parameter (must be power of 2, > 1)
     * @param r Block size parameter
     * @param p Parallelization parameter
     */
    static void derive_key(
        std::span<uint8_t> out,
        std::span<const uint8_t> password,
        std::span<const uint8_t> salt,
        uint32_t N,
        uint32_t r,
        uint32_t p) noexcept;
};

} // namespace nit::crypto::osnova
