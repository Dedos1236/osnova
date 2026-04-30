#include "blake2b.h"
#include <cstring>
#include <array>

namespace nit::crypto::osnova {

namespace {

constexpr uint64_t IV[8] = {
    0x6a09e667f3bcc908ULL, 0xbb67ae8584caa73bULL,
    0x3c6ef372fe94f82bULL, 0xa54ff53a5f1d36f1ULL,
    0x510e527fade682d1ULL, 0x9b05688c2b3e6c1fULL,
    0x1f83d9abfb41bd6bULL, 0x5be0cd19137e2179ULL
};

constexpr uint8_t SIGMA[12][16] = {
    {  0,  1,  2,  3,  4,  5,  6,  7,  8,  9, 10, 11, 12, 13, 14, 15 },
    { 14, 10,  4,  8,  9, 15, 13,  6,  1, 12,  0,  2, 11,  7,  5,  3 },
    { 11,  8, 12,  0,  5,  2, 15, 13, 10, 14,  3,  6,  7,  1,  9,  4 },
    {  7,  9,  3,  1, 13, 12, 11, 14,  2,  6,  5, 10,  4,  0, 15,  8 },
    {  9,  0,  5,  7,  2,  4, 10, 15, 14,  1, 11, 12,  6,  8,  3, 13 },
    {  2, 12,  6, 10,  0, 11,  8,  3,  4, 13,  7,  5, 15, 14,  1,  9 },
    { 12,  5,  1, 15, 14, 13,  4, 10,  0,  7,  6,  3,  9,  2,  8, 11 },
    { 13, 11,  7, 14, 12,  1,  3,  9,  5,  0, 15,  4,  8,  6,  2, 10 },
    {  6, 15, 14,  9, 11,  3,  0,  8, 12,  2, 13,  7,  1,  4, 10,  5 },
    { 10,  2,  8,  4,  7,  6,  1,  5, 15, 11,  9, 14,  3, 12, 13,  0 },
    {  0,  1,  2,  3,  4,  5,  6,  7,  8,  9, 10, 11, 12, 13, 14, 15 },
    { 14, 10,  4,  8,  9, 15, 13,  6,  1, 12,  0,  2, 11,  7,  5,  3 }
};

inline uint64_t rotr64(uint64_t w, unsigned c) {
    return (w >> c) | (w << (64 - c));
}

inline uint64_t load64(const void* src) {
    uint64_t w;
    std::memcpy(&w, src, sizeof(w));
    return w; // Assumes little-endian host. In real impl, check endianness.
}

inline void store64(void* dst, uint64_t w) {
    std::memcpy(dst, &w, sizeof(w));
}

inline void G(uint64_t& a, uint64_t& b, uint64_t& c, uint64_t& d, uint64_t x, uint64_t y) {
    a = a + b + x;
    d = rotr64(d ^ a, 32);
    c = c + d;
    b = rotr64(b ^ c, 24);
    a = a + b + y;
    d = rotr64(d ^ a, 16);
    c = c + d;
    b = rotr64(b ^ c, 63);
}

} // anonymous namespace

void Blake2b::hash(
    std::span<uint8_t> out,
    std::span<const uint8_t> in,
    std::span<const uint8_t> key) noexcept 
{
    if (out.empty() || out.size() > MAX_DIGEST_SIZE || key.size() > MAX_KEY_SIZE) return;

    Blake2b b;
    b.init(out.size(), key);
    b.update(in);
    b.finalize(out);
}

void Blake2b::init(size_t out_len, std::span<const uint8_t> key) noexcept {
    if (out_len == 0 || out_len > MAX_DIGEST_SIZE) return;
    if (key.size() > MAX_KEY_SIZE) return;

    outlen = out_len;
    for (int i = 0; i < 8; ++i) {
        h[i] = IV[i];
    }
    
    // Parameter block
    h[0] ^= 0x01010000 ^ (static_cast<uint64_t>(key.size()) << 8) ^ static_cast<uint64_t>(outlen);

    t[0] = 0;
    t[1] = 0;
    f[0] = 0;
    f[1] = 0;

    buflen = 0;
    std::memset(buf, 0, BLOCK_SIZE);

    if (!key.empty()) {
        std::array<uint8_t, BLOCK_SIZE> block = {0};
        std::memcpy(block.data(), key.data(), key.size());
        update(std::span<const uint8_t>(block.data(), BLOCK_SIZE));
    }
}

void Blake2b::update(std::span<const uint8_t> in) noexcept {
    size_t in_len = in.size();
    const uint8_t* in_data = in.data();

    while (in_len > 0) {
        size_t left = buflen;
        size_t fill = BLOCK_SIZE - left;

        if (in_len > fill) {
            std::memcpy(buf + left, in_data, fill);
            buflen += fill;
            compress(false);
            in_data += fill;
            in_len -= fill;
        } else {
            std::memcpy(buf + left, in_data, in_len);
            buflen += in_len;
            break;
        }
    }
}

void Blake2b::finalize(std::span<uint8_t> out) noexcept {
    if (out.size() != outlen) return;

    size_t left = buflen;
    std::memset(buf + left, 0, BLOCK_SIZE - left);
    compress(true);

    std::array<uint8_t, 64> final_hash;
    for (int i = 0; i < 8; ++i) {
        store64(final_hash.data() + i * 8, h[i]);
    }

    std::memcpy(out.data(), final_hash.data(), outlen);

    // Clear sensitive data
    std::memset(h, 0, sizeof(h));
    std::memset(buf, 0, sizeof(buf));
}

void Blake2b::compress(bool is_last) noexcept {
    uint64_t m[16];
    for (int i = 0; i < 16; ++i) {
        m[i] = load64(buf + i * 8);
    }

    uint64_t v[16];
    for (int i = 0; i < 8; ++i) {
        v[i] = h[i];
        v[i + 8] = IV[i];
    }

    t[0] += buflen;
    if (t[0] < buflen) {
        t[1]++;
    }

    if (is_last) {
        f[0] = ~0ULL;
    }

    v[12] ^= t[0];
    v[13] ^= t[1];
    v[14] ^= f[0];
    v[15] ^= f[1];

    for (int i = 0; i < 12; ++i) {
        G(v[0], v[4], v[ 8], v[12], m[SIGMA[i][ 0]], m[SIGMA[i][ 1]]);
        G(v[1], v[5], v[ 9], v[13], m[SIGMA[i][ 2]], m[SIGMA[i][ 3]]);
        G(v[2], v[6], v[10], v[14], m[SIGMA[i][ 4]], m[SIGMA[i][ 5]]);
        G(v[3], v[7], v[11], v[15], m[SIGMA[i][ 6]], m[SIGMA[i][ 7]]);
        G(v[0], v[5], v[10], v[15], m[SIGMA[i][ 8]], m[SIGMA[i][ 9]]);
        G(v[1], v[6], v[11], v[12], m[SIGMA[i][10]], m[SIGMA[i][11]]);
        G(v[2], v[7], v[ 8], v[13], m[SIGMA[i][12]], m[SIGMA[i][13]]);
        G(v[3], v[4], v[ 9], v[14], m[SIGMA[i][14]], m[SIGMA[i][15]]);
    }

    for (int i = 0; i < 8; ++i) {
        h[i] ^= v[i] ^ v[i + 8];
    }

    buflen = 0;
}

} // namespace nit::crypto::osnova
