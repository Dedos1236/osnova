#pragma once

#include <cstdint>
#include <span>
#include <array>

namespace nit::crypto::osnova {

/**
 * @brief Zero-allocation ChaCha20 stream cipher implementation.
 * Designed for SIMD optimization feasibility.
 */
class ChaCha20 {
public:
    static constexpr size_t KEY_SIZE = 32;
    static constexpr size_t NONCE_SIZE = 12;
    static constexpr size_t BLOCK_SIZE = 64;

    /**
     * @brief Initialize ChaCha20 state with key, nonce, and starting counter.
     */
    ChaCha20(std::span<const uint8_t, KEY_SIZE> key, 
             std::span<const uint8_t, NONCE_SIZE> nonce, 
             uint32_t counter = 0);

    /**
     * @brief Encrypts/Decrypts input into output. Both spans must be of equal length.
     */
    void process_bytes(std::span<const uint8_t> input, std::span<uint8_t> output);

    /**
     * @brief Generates a raw Keystream block and increments the counter.
     */
    void get_keystream_block(std::span<uint8_t, BLOCK_SIZE> output);

    /**
     * @brief Modify the internal counter securely.
     */
    void set_counter(uint32_t counter) noexcept;

private:
    alignas(16) uint32_t state_[16];
    
    static inline uint32_t rotl32(uint32_t x, int n) noexcept {
        return (x << n) | (x >> (32 - n));
    }
    
    static inline void quarter_round(uint32_t& a, uint32_t& b, uint32_t& c, uint32_t& d) noexcept {
        a += b; d ^= a; d = rotl32(d, 16);
        c += d; b ^= c; b = rotl32(b, 12);
        a += b; d ^= a; d = rotl32(d, 8);
        c += d; b ^= c; b = rotl32(b, 7);
    }
    
    void inner_block(uint32_t out[16]) noexcept;
};

} // namespace nit::crypto::osnova
