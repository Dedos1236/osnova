#include "chacha20.h"
#include <cstring>
#include <bit>

namespace nit::crypto::osnova {

namespace {
    // "expand 32-byte k"
    constexpr uint32_t CONSTANTS[4] = { 0x61707865, 0x3320646e, 0x79622d32, 0x6b206574 };

    inline uint32_t load32_le(const uint8_t* src) noexcept {
        if constexpr (std::endian::native == std::endian::little) {
            uint32_t w;
            std::memcpy(&w, src, sizeof(w));
            return w;
        } else {
            return (uint32_t)(src[0]) | 
                   ((uint32_t)(src[1]) << 8) | 
                   ((uint32_t)(src[2]) << 16) | 
                   ((uint32_t)(src[3]) << 24);
        }
    }

    inline void store32_le(uint8_t* dst, uint32_t w) noexcept {
        if constexpr (std::endian::native == std::endian::little) {
            std::memcpy(dst, &w, sizeof(w));
        } else {
            dst[0] = (uint8_t)(w);
            dst[1] = (uint8_t)(w >> 8);
            dst[2] = (uint8_t)(w >> 16);
            dst[3] = (uint8_t)(w >> 24);
        }
    }
}

ChaCha20::ChaCha20(std::span<const uint8_t, KEY_SIZE> key, 
                   std::span<const uint8_t, NONCE_SIZE> nonce, 
                   uint32_t counter) {
    state_[0] = CONSTANTS[0];
    state_[1] = CONSTANTS[1];
    state_[2] = CONSTANTS[2];
    state_[3] = CONSTANTS[3];

    for (int i = 0; i < 8; ++i) {
        state_[4 + i] = load32_le(key.data() + i * 4);
    }

    state_[12] = counter;
    
    for (int i = 0; i < 3; ++i) {
        state_[13 + i] = load32_le(nonce.data() + i * 4);
    }
}

void ChaCha20::set_counter(uint32_t counter) noexcept {
    state_[12] = counter;
}

void ChaCha20::inner_block(uint32_t out[16]) noexcept {
    std::memcpy(out, state_, 16 * sizeof(uint32_t));

    for (int i = 0; i < 10; ++i) {
        // Odd round
        quarter_round(out[0], out[4], out[8],  out[12]);
        quarter_round(out[1], out[5], out[9],  out[13]);
        quarter_round(out[2], out[6], out[10], out[14]);
        quarter_round(out[3], out[7], out[11], out[15]);
        // Even round
        quarter_round(out[0], out[5], out[10], out[15]);
        quarter_round(out[1], out[6], out[11], out[12]);
        quarter_round(out[2], out[7], out[8],  out[13]);
        quarter_round(out[3], out[4], out[9],  out[14]);
    }

    for (int i = 0; i < 16; ++i) {
        out[i] += state_[i];
    }
}

void ChaCha20::get_keystream_block(std::span<uint8_t, BLOCK_SIZE> output) {
    uint32_t block[16];
    inner_block(block);
    ++state_[12]; // increment counter

    for (int i = 0; i < 16; ++i) {
        store32_le(output.data() + (i * 4), block[i]);
    }
}

void ChaCha20::process_bytes(std::span<const uint8_t> input, std::span<uint8_t> output) {
    uint8_t block[BLOCK_SIZE];
    size_t length = input.size();
    size_t offset = 0;

    while (length > 0) {
        uint32_t block_st[16];
        inner_block(block_st);
        ++state_[12];

        for (int i = 0; i < 16; ++i) {
            store32_le(block + (i * 4), block_st[i]);
        }

        size_t chunk = (length < BLOCK_SIZE) ? length : BLOCK_SIZE;
        for (size_t i = 0; i < chunk; ++i) {
            output[offset + i] = input[offset + i] ^ block[i];
        }

        length -= chunk;
        offset += chunk;
    }
    
    // Secure wipe memory
    std::memset(block, 0, sizeof(block));
}

} // namespace nit::crypto::osnova
