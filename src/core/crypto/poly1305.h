#pragma once

#include <cstdint>
#include <span>
#include <array>

namespace nit::crypto::osnova {

/**
 * @brief Poly1305 Message Authentication Code (MAC) implementation.
 * Computes a 16-byte authenticator of a message using a one-time 32-byte key.
 */
class Poly1305 {
public:
    static constexpr size_t KEY_SIZE = 32;
    static constexpr size_t MAC_SIZE = 16;
    static constexpr size_t BLOCK_SIZE = 16;

    /**
     * @brief Initialize Poly1305 with a 32-byte key.
     * The first 16 bytes are 'r', the second 16 bytes are 's'.
     */
    explicit Poly1305(std::span<const uint8_t, KEY_SIZE> key) noexcept;
    
    ~Poly1305();
    
    // Wipe memory on destroy, no copy
    Poly1305(const Poly1305&) = delete;
    Poly1305& operator=(const Poly1305&) = delete;

    /**
     * @brief Process message in arbitrary sized chunks.
     */
    void update(std::span<const uint8_t> data) noexcept;

    /**
     * @brief Finalize and output the 16-byte MAC.
     */
    void finalize(std::span<uint8_t, MAC_SIZE> mac) noexcept;

private:
    uint32_t r_[4];
    uint32_t s_[4];
    uint32_t h_[5];
    uint8_t  buffer_[BLOCK_SIZE];
    size_t   buffer_length_;

    void process_block(const uint8_t* block, uint32_t block_len) noexcept;
};

} // namespace nit::crypto::osnova
