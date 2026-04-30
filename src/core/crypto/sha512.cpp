#include "sha512.h"
#include <cstring>
#include <bit>

namespace nit::crypto::osnova {

namespace {
    constexpr uint64_t K[80] = {
        0x428a2f98d728ae22ULL, 0x7137449123ef65cdULL, 0xb5c0fbcfec4d3b2fULL, 0xe9b5dba58189dbbcULL,
        0x3956c25bf348b538ULL, 0x59f111f1b605d019ULL, 0x923f82a4af194f9bULL, 0xab1c5ed5da6d8118ULL,
        0xd807aa98a3030242ULL, 0x12835b0145706fbeULL, 0x243185be4ee4b28cULL, 0x550c7dc3d5ffb4e2ULL,
        0x72be5d74f27b896fULL, 0x80deb1fe3b1696b1ULL, 0x9bdc06a725c71235ULL, 0xc19bf174cf692694ULL,
        0xe49b69c19ef14ad2ULL, 0xefbe4786384f25e3ULL, 0x0fc19dc68b8cd5b5ULL, 0x240ca1cc77ac9c65ULL,
        0x2de92c6f592b0275ULL, 0x4a7484aa6ea6e483ULL, 0x5cb0a9dcbd41fbd4ULL, 0x76f988da831153b5ULL,
        0x983e5152ee66dfabULL, 0xa831c66d2db43210ULL, 0xb00327c898fb213fULL, 0xbf597fc7beef0ee4ULL,
        0xc6e00bf33da88fc2ULL, 0xd5a79147930aa725ULL, 0x06ca6351e003826fULL, 0x142929670a0e6e70ULL,
        0x27b70a8546d22ffcULL, 0x2e1b21385c26c926ULL, 0x4d2c6dfc5ac42aedULL, 0x53380d139d95b3dfULL,
        0x650a73548baf63deULL, 0x766a0abb3c77b2a8ULL, 0x81c2c92e47edaee6ULL, 0x92722c851482353bULL,
        0xa2bfe8a14cf10364ULL, 0xa81a664bbc423001ULL, 0xc24b8b70d0f89791ULL, 0xc76c51a30654be30ULL,
        0xd192e819d6ef5218ULL, 0xd69906245565a910ULL, 0xf40e35855771202aULL, 0x106aa07032bbd1b8ULL,
        0x19a4c116b8d2d0c8ULL, 0x1e376c085141ab53ULL, 0x2748774cdf8eeb99ULL, 0x34b0bcb5e19b48a8ULL,
        0x391c0cb3c5c95a63ULL, 0x4ed8aa4ae3418acbULL, 0x5b9cca4f7763e373ULL, 0x682e6ff3d6b2b8a3ULL,
        0x748f82ee5defb2fcULL, 0x78a5636f43172f60ULL, 0x84c87814a1f0ab72ULL, 0x8cc702081a6439ecULL,
        0x90befffa23631e28ULL, 0xa4506cebde82bde9ULL, 0xbef9a3f7b2c67915ULL, 0xc67178f2e372532bULL,
        0xca273eceea26619cULL, 0xd186b8c721c0c207ULL, 0xeada7dd6cde0eb1eULL, 0xf57d4f7fee6ed178ULL,
        0x06f067aa72176fbaULL, 0x0a637dc5a2c898a6ULL, 0x113f9804bef90daeULL, 0x1b710b35131c471bULL,
        0x28db77f523047d84ULL, 0x32caab7b40c72493ULL, 0x3c9ebe0a15c9bebcULL, 0x431d67c49c100d4cULL,
        0x4cc5d4becb3e42b6ULL, 0x597f299cfc657e2aULL, 0x5fcb6fab3ad6faecULL, 0x6c44198c4a475817ULL
    };

    inline uint64_t rotr(uint64_t x, int n) { return (x >> n) | (x << (64 - n)); }
    inline uint64_t ch(uint64_t x, uint64_t y, uint64_t z) { return (x & y) ^ (~x & z); }
    inline uint64_t maj(uint64_t x, uint64_t y, uint64_t z) { return (x & y) ^ (x & z) ^ (y & z); }
    inline uint64_t sig0(uint64_t x) { return rotr(x, 28) ^ rotr(x, 34) ^ rotr(x, 39); }
    inline uint64_t sig1(uint64_t x) { return rotr(x, 14) ^ rotr(x, 18) ^ rotr(x, 41); }
    inline uint64_t Sig0(uint64_t x) { return rotr(x, 1) ^ rotr(x, 8) ^ (x >> 7); }
    inline uint64_t Sig1(uint64_t x) { return rotr(x, 19) ^ rotr(x, 61) ^ (x >> 6); }

    inline uint64_t load64_be(const uint8_t* p) {
        if constexpr (std::endian::native == std::endian::big) {
            uint64_t v;
            std::memcpy(&v, p, 8);
            return v;
        } else {
            return ((uint64_t)p[0] << 56) | ((uint64_t)p[1] << 48) | ((uint64_t)p[2] << 40) | ((uint64_t)p[3] << 32) |
                   ((uint64_t)p[4] << 24) | ((uint64_t)p[5] << 16) | ((uint64_t)p[6] << 8)  | ((uint64_t)p[7]);
        }
    }

    inline void store64_be(uint8_t* p, uint64_t v) {
        if constexpr (std::endian::native == std::endian::big) {
            std::memcpy(p, &v, 8);
        } else {
            p[0] = (uint8_t)(v >> 56); p[1] = (uint8_t)(v >> 48); p[2] = (uint8_t)(v >> 40); p[3] = (uint8_t)(v >> 32);
            p[4] = (uint8_t)(v >> 24); p[5] = (uint8_t)(v >> 16); p[6] = (uint8_t)(v >> 8);  p[7] = (uint8_t)(v);
        }
    }
}

Sha512::Sha512() noexcept {
    state_[0] = 0x6a09e667f3bcc908ULL;
    state_[1] = 0xbb67ae8584caa73bULL;
    state_[2] = 0x3c6ef372fe94f82bULL;
    state_[3] = 0xa54ff53a5f1d36f1ULL;
    state_[4] = 0x510e527fade682d1ULL;
    state_[5] = 0x9b05688c2b3e6c1fULL;
    state_[6] = 0x1f83d9abfb41bd6bULL;
    state_[7] = 0x5be0cd19137e2179ULL;
    bit_count_[0] = 0;
    bit_count_[1] = 0;
}

Sha512::~Sha512() {
    std::memset(state_, 0, sizeof(state_));
    std::memset(buffer_, 0, sizeof(buffer_));
    bit_count_[0] = bit_count_[1] = 0;
}

void Sha512::transform(const uint8_t* block) noexcept {
    uint64_t w[80];
    uint64_t a = state_[0];
    uint64_t b = state_[1];
    uint64_t c = state_[2];
    uint64_t d = state_[3];
    uint64_t e = state_[4];
    uint64_t f = state_[5];
    uint64_t g = state_[6];
    uint64_t h = state_[7];

    for (int i = 0; i < 16; ++i) {
        w[i] = load64_be(block + i * 8);
    }
    for (int i = 16; i < 80; ++i) {
        w[i] = w[i - 16] + Sig0(w[i - 15]) + w[i - 7] + Sig1(w[i - 2]);
    }

    for (int i = 0; i < 80; ++i) {
        uint64_t t1 = h + sig1(e) + ch(e, f, g) + K[i] + w[i];
        uint64_t t2 = sig0(a) + maj(a, b, c);
        h = g; g = f; f = e; e = d + t1;
        d = c; c = b; b = a; a = t1 + t2;
    }

    state_[0] += a;
    state_[1] += b;
    state_[2] += c;
    state_[3] += d;
    state_[4] += e;
    state_[5] += f;
    state_[6] += g;
    state_[7] += h;

    std::memset(w, 0, sizeof(w)); // Wipe w
}

void Sha512::update(std::span<const uint8_t> data) noexcept {
    size_t length = data.size();
    const uint8_t* p = data.data();

    // Update bit count
    uint64_t old_bit_count = bit_count_[0];
    bit_count_[0] += (length << 3);
    if (bit_count_[0] < old_bit_count) {
        bit_count_[1]++;
    }
    bit_count_[1] += (length >> 61);

    size_t buffer_len = (old_bit_count >> 3) & 0x7F; // % 128

    if (buffer_len > 0) {
        size_t available = BLOCK_SIZE - buffer_len;
        size_t to_copy = (length < available) ? length : available;
        std::memcpy(buffer_ + buffer_len, p, to_copy);
        length -= to_copy;
        p += to_copy;
        buffer_len += to_copy;

        if (buffer_len == BLOCK_SIZE) {
            transform(buffer_);
        } else {
            return;
        }
    }

    while (length >= BLOCK_SIZE) {
        transform(p);
        p += BLOCK_SIZE;
        length -= BLOCK_SIZE;
    }

    if (length > 0) {
        std::memcpy(buffer_, p, length);
    }
}

void Sha512::finalize(std::span<uint8_t, DIGEST_SIZE> digest) noexcept {
    size_t buffer_len = (bit_count_[0] >> 3) & 0x7F;
    buffer_[buffer_len++] = 0x80;

    if (buffer_len > BLOCK_SIZE - 16) {
        while (buffer_len < BLOCK_SIZE) {
            buffer_[buffer_len++] = 0;
        }
        transform(buffer_);
        buffer_len = 0;
    }

    while (buffer_len < BLOCK_SIZE - 16) {
        buffer_[buffer_len++] = 0;
    }

    store64_be(buffer_ + BLOCK_SIZE - 16, bit_count_[1]);
    store64_be(buffer_ + BLOCK_SIZE - 8, bit_count_[0]);

    transform(buffer_);

    for (int i = 0; i < 8; ++i) {
        store64_be(digest.data() + i * 8, state_[i]);
    }
}

void Sha512::hash(std::span<const uint8_t> data, std::span<uint8_t, DIGEST_SIZE> digest) noexcept {
    Sha512 sha;
    sha.update(data);
    sha.finalize(digest);
}

} // namespace nit::crypto::osnova
