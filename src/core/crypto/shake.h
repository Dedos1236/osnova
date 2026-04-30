#pragma once

#include <cstdint>
#include <span>

namespace nit::crypto::osnova {

/**
 * @brief SHAKE128 and SHAKE256 extendable-output functions (XOFs) from FIPS 202.
 * Crucial for post-quantum algorithms like Kyber and Dilithium.
 */
class Shake {
public:
    /**
     * @brief Compute SHAKE128.
     * 
     * @param out Output buffer of desired length.
     * @param in Input message.
     */
    static void shake128(std::span<uint8_t> out, std::span<const uint8_t> in) noexcept;

    /**
     * @brief Compute SHAKE256.
     * 
     * @param out Output buffer of desired length.
     * @param in Input message.
     */
    static void shake256(std::span<uint8_t> out, std::span<const uint8_t> in) noexcept;
};

} // namespace nit::crypto::osnova
