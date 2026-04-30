#include "scrypt.h"
#include "pbkdf2_hmac_sha256.h"
#include <vector>
#include <cstring>
#include <memory>

namespace nit::crypto::osnova {

namespace {

#define R(a,b) (((a) << (b)) | ((a) >> (32 - (b))))

inline void salsa20_8_core(uint32_t out[16], const uint32_t in[16]) {
    uint32_t x[16];
    for (int i = 0; i < 16; ++i) x[i] = in[i];

    for (int i = 0; i < 8; i += 2) {
        x[ 4] ^= R(x[ 0] + x[12],  7);  x[ 8] ^= R(x[ 4] + x[ 0],  9);
        x[12] ^= R(x[ 8] + x[ 4], 13);  x[ 0] ^= R(x[12] + x[ 8], 18);
        x[ 9] ^= R(x[ 5] + x[ 1],  7);  x[13] ^= R(x[ 9] + x[ 5],  9);
        x[ 1] ^= R(x[13] + x[ 9], 13);  x[ 5] ^= R(x[ 1] + x[13], 18);
        x[14] ^= R(x[10] + x[ 6],  7);  x[ 2] ^= R(x[14] + x[10],  9);
        x[ 6] ^= R(x[ 2] + x[14], 13);  x[10] ^= R(x[ 6] + x[ 2], 18);
        x[ 3] ^= R(x[15] + x[11],  7);  x[ 7] ^= R(x[ 3] + x[15],  9);
        x[11] ^= R(x[ 7] + x[ 3], 13);  x[15] ^= R(x[11] + x[ 7], 18);
        
        x[ 1] ^= R(x[ 0] + x[ 3],  7);  x[ 2] ^= R(x[ 1] + x[ 0],  9);
        x[ 3] ^= R(x[ 2] + x[ 1], 13);  x[ 0] ^= R(x[ 3] + x[ 2], 18);
        x[ 6] ^= R(x[ 5] + x[ 4],  7);  x[ 7] ^= R(x[ 6] + x[ 5],  9);
        x[ 4] ^= R(x[ 7] + x[ 6], 13);  x[ 5] ^= R(x[ 4] + x[ 7], 18);
        x[11] ^= R(x[10] + x[ 9],  7);  x[ 8] ^= R(x[11] + x[10],  9);
        x[ 9] ^= R(x[ 8] + x[11], 13);  x[10] ^= R(x[ 9] + x[ 8], 18);
        x[12] ^= R(x[15] + x[14],  7);  x[13] ^= R(x[12] + x[15],  9);
        x[14] ^= R(x[13] + x[12], 13);  x[15] ^= R(x[14] + x[13], 18);
    }

    for (int i = 0; i < 16; ++i) out[i] = in[i] + x[i];
}

#undef R

inline uint32_t load32_le(const uint8_t* p) {
    return static_cast<uint32_t>(p[0]) |
           (static_cast<uint32_t>(p[1]) << 8) |
           (static_cast<uint32_t>(p[2]) << 16) |
           (static_cast<uint32_t>(p[3]) << 24);
}

inline void store32_le(uint8_t* p, uint32_t v) {
    p[0] = static_cast<uint8_t>(v);
    p[1] = static_cast<uint8_t>(v >> 8);
    p[2] = static_cast<uint8_t>(v >> 16);
    p[3] = static_cast<uint8_t>(v >> 24);
}

void blockmix_salsa8(const uint8_t* B, uint8_t* Y, uint32_t r) {
    uint32_t X[16];
    uint32_t T[16];

    for (int i = 0; i < 16; ++i) {
        X[i] = load32_le(&B[(2 * r - 1) * 64 + i * 4]);
    }

    for (uint32_t i = 0; i < 2 * r; ++i) {
        for (int j = 0; j < 16; ++j) {
            X[j] ^= load32_le(&B[i * 64 + j * 4]);
        }
        
        salsa20_8_core(T, X);
        
        for (int j = 0; j < 16; ++j) {
            X[j] = T[j];
        }

        uint8_t* dest;
        if (i % 2 == 0) {
            dest = &Y[(i / 2) * 64];
        } else {
            dest = &Y[(r + i / 2) * 64];
        }

        for (int j = 0; j < 16; ++j) {
            store32_le(&dest[j * 4], X[j]);
        }
    }
}

uint64_t integerify(const uint8_t* B, uint32_t r) {
    const uint8_t* X = &B[(2 * r - 1) * 64];
    uint32_t v = load32_le(X);
    return static_cast<uint64_t>(v); // for N <= 2^32, the first 32 bits are sufficient
}

void smix(uint8_t* B, uint32_t r, uint32_t N, std::vector<uint8_t>& V, std::vector<uint8_t>& XY) {
    uint8_t* X = XY.data();
    uint8_t* Y = XY.data() + 128 * r;

    std::memcpy(X, B, 128 * r);

    for (uint32_t i = 0; i < N; ++i) {
        std::memcpy(&V[i * (128 * r)], X, 128 * r);
        blockmix_salsa8(X, Y, r);
        std::memcpy(X, Y, 128 * r); // The original paper definition swaps X and Y or copies. The exact way blockmix places in Y requires copy back.
    }

    for (uint32_t i = 0; i < N; ++i) {
        uint32_t j = integerify(X, r) & (N - 1);
        for (uint32_t k = 0; k < 128 * r; ++k) {
            X[k] ^= V[j * (128 * r) + k];
        }
        blockmix_salsa8(X, Y, r);
        std::memcpy(X, Y, 128 * r);
    }

    std::memcpy(B, X, 128 * r);
}

} // anonymous namespace

void Scrypt::derive_key(
    std::span<uint8_t> out,
    std::span<const uint8_t> password,
    std::span<const uint8_t> salt,
    uint32_t N,
    uint32_t r,
    uint32_t p) noexcept 
{
    if (out.empty() || N < 2 || (N & (N - 1)) != 0 || r == 0 || p == 0) return;

    size_t B_len = 128 * r * p;
    std::vector<uint8_t> B(B_len, 0);

    // 1. Pbkdf2 iteration
    Pbkdf2HmacSha256::derive_key(std::span<uint8_t>(B.data(), B_len), password, salt, 1);

    // Allocate once for all p threads
    std::vector<uint8_t> V(128 * r * N, 0);
    std::vector<uint8_t> XY(256 * r, 0);

    // 2. SMix
    for (uint32_t i = 0; i < p; ++i) {
        smix(&B[i * 128 * r], r, N, V, XY);
    }

    // 3. Pbkdf2 iteration
    Pbkdf2HmacSha256::derive_key(out, password, std::span<const uint8_t>(B.data(), B_len), 1);

    // Clean up
    std::memset(B.data(), 0, B.size());
    std::memset(V.data(), 0, V.size());
    std::memset(XY.data(), 0, XY.size());
}

} // namespace nit::crypto::osnova
