#pragma once

#include <cstdint>
#include <span>
#include <vector>

namespace nit::crypto::osnova {

/**
 * @brief HMAC-DRBG implementation based on HMAC-SHA256.
 * NIST SP 800-90A.
 */
class HmacDrbg {
public:
    static constexpr size_t SEED_LEN = 256 / 8; // We require 256 bits of entropy

    HmacDrbg() noexcept = default;

    /**
     * @brief Initialize the DRBG.
     * 
     * @param entropy Input entropy (should be high quality)
     * @param nonce Nonce
     * @param personalization_string Optional personalization string
     */
    void instantiate(
        std::span<const uint8_t> entropy,
        std::span<const uint8_t> nonce = {},
        std::span<const uint8_t> personalization_string = {}) noexcept;

    /**
     * @brief Reseed the DRBG.
     * 
     * @param entropy Input entropy
     * @param additional_input Optional additional input
     */
    void reseed(
        std::span<const uint8_t> entropy,
        std::span<const uint8_t> additional_input = {}) noexcept;

    /**
     * @brief Generate random bytes.
     * 
     * @param out Buffer to fill
     * @param additional_input Optional additional input
     * @return true if successful, false if reseed is required
     */
    bool generate(
        std::span<uint8_t> out,
        std::span<const uint8_t> additional_input = {}) noexcept;

private:
    void update(std::span<const uint8_t> provided_data) noexcept;
    void update_multiple(std::span<const uint8_t> data1, std::span<const uint8_t> data2, std::span<const uint8_t> data3) noexcept;

    std::vector<uint8_t> V;
    std::vector<uint8_t> Key;
    uint64_t reseed_counter = 0;
    static constexpr uint64_t RESEED_INTERVAL = 10000;
};

} // namespace nit::crypto::osnova
