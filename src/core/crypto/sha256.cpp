#include "sha256.h"
#include <cstring>
#include <bit>

namespace nit::crypto::osnova {

namespace {
    const uint32_t K256[64] = {
        0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5,
        0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3, 0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174,
        0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc, 0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
        0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7, 0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967,
        0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13, 0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85,
        0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
        0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
        0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208, 0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2
    };

    inline uint32_t rotr32(uint32_t x, int n) {
        return (x >> n) | (x << (32 - n));
    }

    inline uint32_t load32_be(const uint8_t* p) {
        if constexpr (std::endian::native == std::endian::big) {
            uint32_t v;
            std::memcpy(&v, p, 4);
            return v;
        } else {
            return ((uint32_t)p[0] << 24) | ((uint32_t)p[1] << 16) | ((uint32_t)p[2] << 8) | ((uint32_t)p[3]);
        }
    }

    inline void store32_be(uint8_t* p, uint32_t v) {
        if constexpr (std::endian::native == std::endian::big) {
            std::memcpy(p, &v, 4);
        } else {
            p[0] = v >> 24; p[1] = v >> 16; p[2] = v >> 8; p[3] = v;
        }
    }
}

Sha256::Sha256() noexcept {
    state_[0] = 0x6a09e667;
    state_[1] = 0xbb67ae85;
    state_[2] = 0x3c6ef372;
    state_[3] = 0xa54ff53a;
    state_[4] = 0x510e527f;
    state_[5] = 0x9b05688c;
    state_[6] = 0x1f83d9ab;
    state_[7] = 0x5be0cd19;
    total_length_ = 0;
    buffer_length_ = 0;
}

void Sha256::process_block(const uint8_t* block) noexcept {
    uint32_t w[64];
    for (int i = 0; i < 16; ++i) {
        w[i] = load32_be(block + i * 4);
    }
    for (int i = 16; i < 64; ++i) {
        uint32_t s0 = rotr32(w[i - 15], 7) ^ rotr32(w[i - 15], 18) ^ (w[i - 15] >> 3);
        uint32_t s1 = rotr32(w[i - 2], 17) ^ rotr32(w[i - 2], 19) ^ (w[i - 2] >> 10);
        w[i] = w[i - 16] + s0 + w[i - 7] + s1;
    }

    uint32_t a = state_[0];
    uint32_t b = state_[1];
    uint32_t c = state_[2];
    uint32_t d = state_[3];
    uint32_t e = state_[4];
    uint32_t f = state_[5];
    uint32_t g = state_[6];
    uint32_t h = state_[7];

    for (int i = 0; i < 64; ++i) {
        uint32_t S1 = rotr32(e, 6) ^ rotr32(e, 11) ^ rotr32(e, 25);
        uint32_t ch = (e & f) ^ (~e & g);
        uint32_t temp1 = h + S1 + ch + K256[i] + w[i];
        uint32_t S0 = rotr32(a, 2) ^ rotr32(a, 13) ^ rotr32(a, 22);
        uint32_t maj = (a & b) ^ (a & c) ^ (b & c);
        uint32_t temp2 = S0 + maj;

        h = g;
        g = f;
        f = e;
        e = d + temp1;
        d = c;
        c = b;
        b = a;
        a = temp1 + temp2;
    }

    state_[0] += a;
    state_[1] += b;
    state_[2] += c;
    state_[3] += d;
    state_[4] += e;
    state_[5] += f;
    state_[6] += g;
    state_[7] += h;
}

void Sha256::update(std::span<const uint8_t> data) noexcept {
    size_t in_len = data.size();
    const uint8_t* in = data.data();
    
    total_length_ += in_len;

    if (buffer_length_ > 0) {
        size_t space = 64 - buffer_length_;
        if (in_len >= space) {
            std::memcpy(buffer_ + buffer_length_, in, space);
            process_block(buffer_);
            in += space;
            in_len -= space;
            buffer_length_ = 0;
        } else {
            std::memcpy(buffer_ + buffer_length_, in, in_len);
            buffer_length_ += in_len;
            return;
        }
    }

    while (in_len >= 64) {
        process_block(in);
        in += 64;
        in_len -= 64;
    }

    if (in_len > 0) {
        std::memcpy(buffer_, in, in_len);
        buffer_length_ = in_len;
    }
}

void Sha256::finalize(std::span<uint8_t, DIGEST_SIZE> digest) noexcept {
    uint8_t count[8];
    uint64_t bits = total_length_ * 8;
    
    // Store bit length big-endian
    for (int i = 0; i < 8; ++i) {
        count[i] = (bits >> (56 - 8 * i)) & 0xFF;
    }

    uint8_t pad = 0x80;
    update(std::span<const uint8_t>(&pad, 1));
    
    while (buffer_length_ != 56) {
        pad = 0x00;
        update(std::span<const uint8_t>(&pad, 1));
    }

    update(std::span<const uint8_t>(count, 8));

    for (int i = 0; i < 8; ++i) {
        store32_be(digest.data() + i * 4, state_[i]);
    }
}

} // namespace nit::crypto::osnova
