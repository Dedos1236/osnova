#include "sha3.h"
#include <cstring>
#include <bit>

namespace nit::crypto::osnova {

namespace {
    inline uint64_t rotl64(uint64_t x, int n) {
        return (x << n) | (x >> (64 - n));
    }

    constexpr uint64_t KECCAK_ROUND_CONSTANTS[24] = {
        0x0000000000000001ULL, 0x0000000000008082ULL, 0x800000000000808aULL,
        0x8000000080008000ULL, 0x000000000000808bULL, 0x0000000080000001ULL,
        0x8000000080008081ULL, 0x8000000000008009ULL, 0x000000000000008aULL,
        0x0000000000000088ULL, 0x0000000080008009ULL, 0x000000008000000aULL,
        0x000000008000808bULL, 0x800000000000008bULL, 0x8000000000008089ULL,
        0x8000000000008003ULL, 0x8000000000008002ULL, 0x8000000000000080ULL,
        0x000000000000800aULL, 0x800000008000000aULL, 0x8000000080008081ULL,
        0x8000000000008080ULL, 0x0000000080000001ULL, 0x8000000080008008ULL
    };

    constexpr int KECCAK_ROTATION_OFFSETS[25] = {
         0,  1, 62, 28, 27,
        36, 44,  6, 55, 20,
         3, 10, 43, 25, 39,
        41, 45, 15, 21,  8,
        18,  2, 61, 56, 14
    };

    uint64_t load64_le(const uint8_t* b) {
        if constexpr (std::endian::native == std::endian::little) {
            uint64_t v;
            std::memcpy(&v, b, 8);
            return v;
        } else {
            return ((uint64_t)b[0]) | ((uint64_t)b[1] << 8) | ((uint64_t)b[2] << 16) |
                   ((uint64_t)b[3] << 24) | ((uint64_t)b[4] << 32) | ((uint64_t)b[5] << 40) |
                   ((uint64_t)b[6] << 48) | ((uint64_t)b[7] << 56);
        }
    }

    void store64_le(uint8_t* b, uint64_t v) {
        if constexpr (std::endian::native == std::endian::little) {
            std::memcpy(b, &v, 8);
        } else {
            b[0] = v & 0xFF; b[1] = (v >> 8) & 0xFF; b[2] = (v >> 16) & 0xFF; b[3] = (v >> 24) & 0xFF;
            b[4] = (v >> 32) & 0xFF; b[5] = (v >> 40) & 0xFF; b[6] = (v >> 48) & 0xFF; b[7] = (v >> 56) & 0xFF;
        }
    }
}

void Sha3::keccak_f1600(uint64_t state[KECCAK_STATE_WORDS]) noexcept {
    uint64_t B[5], C[5], D[5];

    for (int round = 0; round < 24; round++) {
        // Theta
        for (int i = 0; i < 5; i++) {
            C[i] = state[i] ^ state[i + 5] ^ state[i + 10] ^ state[i + 15] ^ state[i + 20];
        }
        for (int i = 0; i < 5; i++) {
            D[i] = C[(i + 4) % 5] ^ rotl64(C[(i + 1) % 5], 1);
        }
        for (int i = 0; i < 5; i++) {
            for (int j = 0; j < 25; j += 5) {
                state[i + j] ^= D[i];
            }
        }

        // Rho & Pi
        uint64_t prev = state[1];
        for (int i = 0; i < 24; i++) {
            int j = KECCAK_ROTATION_OFFSETS[i + 1];
            uint64_t curr = state[(i * 12 + 10) % 25];
            state[(i * 12 + 10) % 25] = rotl64(prev, j);
            prev = curr;
        }

        // Chi
        for (int j = 0; j < 25; j += 5) {
            for (int i = 0; i < 5; i++) {
                B[i] = state[j + i];
            }
            for (int i = 0; i < 5; i++) {
                state[j + i] ^= (~B[(i + 1) % 5]) & B[(i + 2) % 5];
            }
        }

        // Iota
        state[0] ^= KECCAK_ROUND_CONSTANTS[round];
    }
}

Sha3::Sha3() noexcept {
    init(Type::SHA3_256);
}

void Sha3::init(Type type) noexcept {
    std::memset(state_, 0, sizeof(state_));
    byte_io_index_ = 0;
    absorbing_ = true;

    switch (type) {
        case Type::SHA3_256:
            rate_bytes_ = 1088 / 8; // 136
            capacity_bytes_ = 512 / 8; // 64
            suffix_ = 0x06;
            break;
        case Type::SHA3_512:
            rate_bytes_ = 576 / 8; // 72
            capacity_bytes_ = 1024 / 8; // 128
            suffix_ = 0x06;
            break;
        case Type::SHAKE128:
            rate_bytes_ = 1344 / 8; // 168
            capacity_bytes_ = 256 / 8; // 32
            suffix_ = 0x1F;
            break;
        case Type::SHAKE256:
            rate_bytes_ = 1088 / 8; // 136
            capacity_bytes_ = 512 / 8; // 64
            suffix_ = 0x1F;
            break;
    }
}

void Sha3::absorb_block(const uint8_t* in) noexcept {
    for (uint32_t i = 0; i < rate_bytes_ / 8; i++) {
        state_[i] ^= load64_le(in + i * 8);
    }
    keccak_f1600(state_);
}

void Sha3::update(std::span<const uint8_t> data) noexcept {
    if (!absorbing_) return; // Error in protocol

    size_t length = data.size();
    const uint8_t* in = data.data();

    // Partial block
    if (byte_io_index_ > 0) {
        size_t available = rate_bytes_ - byte_io_index_;
        size_t to_copy = (length < available) ? length : available;

        uint8_t state_bytes[200];
        for (int i=0; i<25; i++) store64_le(state_bytes + i*8, state_[i]);
        for (size_t i=0; i<to_copy; i++) state_bytes[byte_io_index_ + i] ^= in[i];
        for (int i=0; i<25; i++) state_[i] = load64_le(state_bytes + i*8);

        byte_io_index_ += to_copy;
        length -= to_copy;
        in += to_copy;

        if (byte_io_index_ == rate_bytes_) {
            keccak_f1600(state_);
            byte_io_index_ = 0;
        } else {
            return;
        }
    }

    // Full blocks
    while (length >= rate_bytes_) {
        absorb_block(in);
        in += rate_bytes_;
        length -= rate_bytes_;
    }

    // Remaining
    if (length > 0) {
        uint8_t state_bytes[200];
        for (int i=0; i<25; i++) store64_le(state_bytes + i*8, state_[i]);
        for (size_t i=0; i<length; i++) state_bytes[byte_io_index_ + i] ^= in[i];
        for (int i=0; i<25; i++) state_[i] = load64_le(state_bytes + i*8);
        byte_io_index_ += length;
    }
}

void Sha3::finalize(std::span<uint8_t> digest) noexcept {
    if (!absorbing_) return;

    // Pad
    uint8_t state_bytes[200];
    for (int i=0; i<25; i++) store64_le(state_bytes + i*8, state_[i]);

    state_bytes[byte_io_index_] ^= suffix_;
    state_bytes[rate_bytes_ - 1] ^= 0x80;

    for (int i=0; i<25; i++) state_[i] = load64_le(state_bytes + i*8);

    keccak_f1600(state_);
    absorbing_ = false;
    byte_io_index_ = 0;

    squeeze(digest);
}

void Sha3::squeeze(std::span<uint8_t> out) noexcept {
    size_t length = out.size();
    uint8_t* out_ptr = out.data();

    // If we haven't padded yet, pad. If we did, just squeeze.
    if (absorbing_) {
        // Pad for SHAKE
        uint8_t state_bytes[200];
        for (int i=0; i<25; i++) store64_le(state_bytes + i*8, state_[i]);

        state_bytes[byte_io_index_] ^= suffix_;
        state_bytes[rate_bytes_ - 1] ^= 0x80;

        for (int i=0; i<25; i++) state_[i] = load64_le(state_bytes + i*8);

        keccak_f1600(state_);
        absorbing_ = false;
        byte_io_index_ = 0;
    }

    while (length > 0) {
        uint8_t state_bytes[200];
        for (int i=0; i<25; i++) store64_le(state_bytes + i*8, state_[i]);

        size_t available = rate_bytes_ - byte_io_index_;
        size_t to_copy = (length < available) ? length : available;

        std::memcpy(out_ptr, state_bytes + byte_io_index_, to_copy);
        
        byte_io_index_ += to_copy;
        out_ptr += to_copy;
        length -= to_copy;

        if (byte_io_index_ == rate_bytes_) {
            keccak_f1600(state_);
            byte_io_index_ = 0;
        }
    }
}

} // namespace nit::crypto::osnova
