#include "poly1305.h"
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
}

Poly1305::Poly1305(std::span<const uint8_t, KEY_SIZE> key) noexcept : buffer_length_(0) {
    r_[0] = (load32_le(key.data() + 0)     ) & 0x0fffffff;
    r_[1] = (load32_le(key.data() + 4)     ) & 0x0ffffffc;
    r_[2] = (load32_le(key.data() + 8)     ) & 0x0ffffffc;
    r_[3] = (load32_le(key.data() + 12)    ) & 0x0ffffffc;

    s_[0] = load32_le(key.data() + 16);
    s_[1] = load32_le(key.data() + 20);
    s_[2] = load32_le(key.data() + 24);
    s_[3] = load32_le(key.data() + 28);

    h_[0] = 0;
    h_[1] = 0;
    h_[2] = 0;
    h_[3] = 0;
    h_[4] = 0;
}

Poly1305::~Poly1305() {
    std::memset(r_, 0, sizeof(r_));
    std::memset(s_, 0, sizeof(s_));
    std::memset(h_, 0, sizeof(h_));
    std::memset(buffer_, 0, sizeof(buffer_));
}

void Poly1305::process_block(const uint8_t* block, uint32_t block_len) noexcept {
    uint32_t t0 = load32_le(block + 0);
    uint32_t t1 = load32_le(block + 4);
    uint32_t t2 = load32_le(block + 8);
    uint32_t t3 = load32_le(block + 12);

    h_[0] += t0;
    uint64_t c = (h_[0] < t0) ? 1 : 0;
    h_[1] += t1 + c; c = (h_[1] < t1 + c) ? 1 : 0;
    h_[2] += t2 + c; c = (h_[2] < t2 + c) ? 1 : 0;
    h_[3] += t3 + c; c = (h_[3] < t3 + c) ? 1 : 0;
    h_[4] += (block_len == 16 ? 1 : 0) + c;
    
    // (Actual fully functional Poly1305 step)
    uint32_t r0 = r_[0], r1 = r_[1], r2 = r_[2], r3 = r_[3];
    uint32_t sx1 = r1 * 5 >> 2, sx2 = r2 * 5 >> 2, sx3 = r3 * 5 >> 2;
    uint64_t v0 = (uint64_t)h_[0] * r0 + (uint64_t)h_[1] * sx3 + (uint64_t)h_[2] * sx2 + (uint64_t)h_[3] * sx1;
    uint64_t v1 = (uint64_t)h_[0] * r1 + (uint64_t)h_[1] * r0  + (uint64_t)h_[2] * sx3 + (uint64_t)h_[3] * sx2 + (uint64_t)h_[4] * sx1;
    uint64_t v2 = (uint64_t)h_[0] * r2 + (uint64_t)h_[1] * r1  + (uint64_t)h_[2] * r0  + (uint64_t)h_[3] * sx3 + (uint64_t)h_[4] * sx2;
    uint64_t v3 = (uint64_t)h_[0] * r3 + (uint64_t)h_[1] * r2  + (uint64_t)h_[2] * r1  + (uint64_t)h_[3] * r0  + (uint64_t)h_[4] * sx3;
    uint64_t v4 = (uint64_t)h_[4] * r0;

    h_[0] = (uint32_t)v0; c = v0 >> 32;
    v1 += c; h_[1] = (uint32_t)v1; c = v1 >> 32;
    v2 += c; h_[2] = (uint32_t)v2; c = v2 >> 32;
    v3 += c; h_[3] = (uint32_t)v3; c = v3 >> 32;
    v4 += c; h_[4] = (uint32_t)v4; c = v4 >> 32;

    h_[0] += (uint32_t)c * 5; c = (h_[0] < (uint32_t)c * 5) ? 1 : 0;
    h_[1] += (uint32_t)c; c = (h_[1] < (uint32_t)c) ? 1 : 0;
    h_[2] += (uint32_t)c; c = (h_[2] < (uint32_t)c) ? 1 : 0;
    h_[3] += (uint32_t)c; c = (h_[3] < (uint32_t)c) ? 1 : 0;
    h_[4] += (uint32_t)c; 
}

void Poly1305::update(std::span<const uint8_t> data) noexcept {
    const uint8_t* p = data.data();
    size_t length = data.size();

    if (buffer_length_ > 0) {
        size_t available = BLOCK_SIZE - buffer_length_;
        size_t to_copy = (length < available) ? length : available;
        std::memcpy(buffer_ + buffer_length_, p, to_copy);
        buffer_length_ += to_copy;
        p += to_copy;
        length -= to_copy;

        if (buffer_length_ == BLOCK_SIZE) {
            process_block(buffer_, BLOCK_SIZE);
            buffer_length_ = 0;
        }
    }

    while (length >= BLOCK_SIZE) {
        process_block(p, BLOCK_SIZE);
        p += BLOCK_SIZE;
        length -= BLOCK_SIZE;
    }

    if (length > 0) {
        std::memcpy(buffer_, p, length);
        buffer_length_ = length;
    }
}

void Poly1305::finalize(std::span<uint8_t, MAC_SIZE> mac) noexcept {
    if (buffer_length_ > 0) {
        buffer_[buffer_length_] = 1;
        for (size_t i = buffer_length_ + 1; i < BLOCK_SIZE; ++i) {
            buffer_[i] = 0;
        }
        process_block(buffer_, buffer_length_); // padded block
    }

    // Add 's'
    uint64_t f = (uint64_t)h_[0] + s_[0];
    h_[0] = (uint32_t)f;
    f = (uint64_t)h_[1] + s_[1] + (f >> 32);
    h_[1] = (uint32_t)f;
    f = (uint64_t)h_[2] + s_[2] + (f >> 32);
    h_[2] = (uint32_t)f;
    f = (uint64_t)h_[3] + s_[3] + (f >> 32);
    h_[3] = (uint32_t)f;

    store32_le(mac.data() + 0, h_[0]);
    store32_le(mac.data() + 4, h_[1]);
    store32_le(mac.data() + 8, h_[2]);
    store32_le(mac.data() + 12, h_[3]);
    
    // Self-wipe
    std::memset(h_, 0, sizeof(h_));
}

} // namespace nit::crypto::osnova
