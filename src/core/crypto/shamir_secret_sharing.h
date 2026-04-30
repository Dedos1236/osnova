#pragma once

#include <cstdint>
#include <span>
#include <vector>

namespace nit::crypto::osnova {

/**
 * @brief Shamir's Secret Sharing over GF(2^8).
 */
class ShamirSecretSharing {
public:
    struct Share {
        uint8_t index; // X coordinate
        std::vector<uint8_t> value; // Y coordinate (split data)
    };

    /**
     * @brief Split a secret into N shares, requiring K shares to reconstruct.
     * 
     * @param secret The secret data.
     * @param n Total number of shares to generate.
     * @param k Threshold number of shares to reconstruct.
     * @return A vector of N shares.
     */
    static std::vector<Share> split(std::span<const uint8_t> secret, uint8_t n, uint8_t k) noexcept;

    /**
     * @brief Reconstruct the secret from a set of shares using Lagrange interpolation.
     * 
     * @param shares A vector of at least K valid shares.
     * @return The reconstructed secret.
     */
    static std::vector<uint8_t> reconstruct(const std::vector<Share>& shares) noexcept;

private:
    static uint8_t gf256_add(uint8_t a, uint8_t b) noexcept;
    static uint8_t gf256_mul(uint8_t a, uint8_t b) noexcept;
    static uint8_t gf256_div(uint8_t a, uint8_t b) noexcept;
    static uint8_t gf256_inv(uint8_t a) noexcept;
};

} // namespace nit::crypto::osnova
