#include "xchacha20.h"
#include "chacha20.h"
#include <cstring>
#include <bit>

namespace nit::crypto::osnova {

namespace {
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

    inline uint32_t rotl32(uint32_t x, int n) noexcept {
        return (x << n) | (x >> (32 - n));
    }

    inline void quarter_round(uint32_t& a, uint32_t& b, uint32_t& c, uint32_t& d) noexcept {
        a += b; d ^= a; d = rotl32(d, 16);
        c += d; b ^= c; b = rotl32(b, 12);
        a += b; d ^= a; d = rotl32(d, 8);
        c += d; b ^= c; b = rotl32(b, 7);
    }
}

void XChaCha20::hchacha20(
    std::span<uint8_t, KEY_SIZE> out,
    std::span<const uint8_t, KEY_SIZE> key,
    std::span<const uint8_t, 16> nonce) noexcept 
{
    uint32_t state[16];
    
    // Constants
    state[0] = 0x61707865;
    state[1] = 0x3320646e;
    state[2] = 0x79622d32;
    state[3] = 0x6b206574;
    
    // Key
    for (int i = 0; i < 8; ++i) {
        state[4 + i] = load32_le(key.data() + i * 4);
    }
    
    // Nonce
    for (int i = 0; i < 4; ++i) {
        state[12 + i] = load32_le(nonce.data() + i * 4);
    }

    // 20 rounds (10 double rounds)
    for (int i = 0; i < 10; ++i) {
        quarter_round(state[0], state[4], state[ 8], state[12]);
        quarter_round(state[1], state[5], state[ 9], state[13]);
        quarter_round(state[2], state[6], state[10], state[14]);
        quarter_round(state[3], state[7], state[11], state[15]);

        quarter_round(state[0], state[5], state[10], state[15]);
        quarter_round(state[1], state[6], state[11], state[12]);
        quarter_round(state[2], state[7], state[ 8], state[13]);
        quarter_round(state[3], state[4], state[ 9], state[14]);
    }

    // HChaCha20 returns the first and last rows of the state
    for (int i = 0; i < 4; ++i) {
        store32_le(out.data() + i * 4, state[i]);
        store32_le(out.data() + 16 + i * 4, state[12 + i]);
    }
}

void XChaCha20::process(
    std::span<uint8_t> out,
    std::span<const uint8_t> in,
    std::span<const uint8_t, KEY_SIZE> key,
    std::span<const uint8_t, NONCE_SIZE> nonce,
    uint32_t counter) noexcept 
{
    uint8_t subkey[32];
    hchacha20(std::span<uint8_t, 32>(subkey, 32), key, std::span<const uint8_t, 16>(nonce.data(), 16));

    // Remaining 8 bytes of the nonce are padded to 12 bytes for normal ChaCha20
    uint8_t chacha_nonce[12] = {0};
    std::memcpy(chacha_nonce + 4, nonce.data() + 16, 8);

    ChaCha20::process(out, in, std::span<const uint8_t, 32>(subkey, 32), std::span<const uint8_t, 12>(chacha_nonce, 12), counter);
    
    std::memset(subkey, 0, sizeof(subkey));
}

} // namespace nit::crypto::osnova
