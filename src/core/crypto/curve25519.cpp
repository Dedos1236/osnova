#include "curve25519.h"
#include <cstring>
#include <algorithm>

namespace nit::crypto::osnova {

// Fully core Montgomery ladder over Galois Field (2^255 - 19)
// Adapted functionally from standard constant-time implementations (TweetNaCl).

static void car25519(Curve25519::limb_t* o) noexcept {
    int64_t c;
    for (int i = 0; i < 16; ++i) {
        o[i] += (1LL << 16);
        c = o[i] >> 16;
        o[(i + 1) * (i < 15 ? 1 : 0)] += c - 1 + 37 * (c - 1) * (i == 15 ? 1 : 0);
        o[i] -= c << 16;
    }
}

static void sel25519(Curve25519::limb_t* p, Curve25519::limb_t* q, int b) noexcept {
    int64_t t, c = ~(b - 1);
    for (int i = 0; i < 16; ++i) {
        t = c & (p[i] ^ q[i]);
        p[i] ^= t;
        q[i] ^= t;
    }
}

static void pack25519(uint8_t* o, const Curve25519::limb_t* n) noexcept {
    int64_t t[16], m[16], b;
    for (int i = 0; i < 16; ++i) t[i] = n[i];
    car25519(t);
    car25519(t);
    car25519(t);
    for (int j = 0; j < 2; ++j) {
        m[0] = t[0] - 0xffed;
        for (int i = 1; i < 15; ++i) {
            m[i] = t[i] - 0xffff - ((m[i - 1] >> 16) & 1);
            m[i - 1] &= 0xffff;
        }
        m[15] = t[15] - 0x7fff - ((m[14] >> 16) & 1);
        b = (m[15] >> 16) & 1;
        m[14] &= 0xffff;
        sel25519(t, m, 1 - b);
    }
    for (int i = 0; i < 16; ++i) {
        o[2 * i] = t[i] & 0xff;
        o[2 * i + 1] = t[i] >> 8;
    }
}

static void unpack25519(Curve25519::limb_t* o, const uint8_t* n) noexcept {
    for (int i = 0; i < 16; ++i) o[i] = n[2 * i] + ((int64_t)n[2 * i + 1] << 8);
    o[15] &= 0x7fff;
}

void Curve25519::fe_0(Fe& h) noexcept {
    for (int i = 0; i < 16; ++i) h.limbs[i] = 0;
}

void Curve25519::fe_1(Fe& h) noexcept {
    h.limbs[0] = 1;
    for (int i = 1; i < 16; ++i) h.limbs[i] = 0;
}

void Curve25519::fe_add(Fe& h, const Fe& f, const Fe& g) noexcept {
    for (int i = 0; i < 16; ++i) h.limbs[i] = f.limbs[i] + g.limbs[i];
}

void Curve25519::fe_sub(Fe& h, const Fe& f, const Fe& g) noexcept {
    for (int i = 0; i < 16; ++i) h.limbs[i] = f.limbs[i] - g.limbs[i];
}

void Curve25519::fe_mul121666(Fe& h, const Fe& f) noexcept {
    for (int i = 0; i < 16; ++i) h.limbs[i] = f.limbs[i] * 121666;
}

void Curve25519::fe_cswap(Fe& f, Fe& g, uint8_t b) noexcept {
    sel25519(f.limbs, g.limbs, b);
}

void Curve25519::fe_frombytes(Fe& h, std::span<const uint8_t, 32> s) noexcept {
    unpack25519(h.limbs, s.data());
}

void Curve25519::fe_tobytes(std::span<uint8_t, 32> s, const Fe& h) noexcept {
    pack25519(s.data(), h.limbs);
}

void Curve25519::fe_mul(Fe& h, const Fe& f, const Fe& g) noexcept {
    int64_t t[31];
    for(int i = 0; i < 31; ++i) t[i] = 0;
    for(int i = 0; i < 16; ++i) {
        for(int j = 0; j < 16; ++j) {
            t[i + j] += f.limbs[i] * g.limbs[j];
        }
    }
    for(int i = 0; i < 15; ++i) t[i] += 38 * t[i + 16];
    for(int i = 0; i < 16; ++i) h.limbs[i] = t[i];
    car25519(h.limbs);
    car25519(h.limbs);
}

void Curve25519::fe_sq(Fe& h, const Fe& f) noexcept {
    fe_mul(h, f, f);
}

void Curve25519::fe_invert(Fe& out, const Fe& z) noexcept {
    Fe c, x11, x22, x33, x44, x55;
    fe_sq(c, z); fe_mul(x11, c, z);
    fe_sq(c, x11); fe_sq(c, c); fe_mul(x22, c, x11);
    fe_sq(c, x22); fe_sq(c, c); fe_sq(c, c); fe_sq(c, c); fe_mul(x33, c, x22);
    fe_sq(c, x33); for(int i=0;i<7;i++) fe_sq(c, c); fe_mul(x44, c, x33);
    fe_sq(c, x44); for(int i=0;i<15;i++) fe_sq(c, c); fe_mul(x55, c, x44);
    fe_sq(c, x55); for(int i=0;i<31;i++) fe_sq(c, c); fe_mul(c, c, x55);
    fe_sq(c, c); for(int i=0;i<63;i++) fe_sq(c, c); fe_mul(c, c, x55);
    fe_sq(c, c); for(int i=0;i<127;i++) fe_sq(c, c); fe_mul(c, c, x44);
    fe_sq(c, c); for(int i=0;i<15;i++) fe_sq(c, c); fe_mul(c, c, x22);
    fe_sq(c, c); fe_sq(c, c); fe_mul(c, c, z);
    for(int i=0; i<16; i++) out.limbs[i] = c.limbs[i];
}

void Curve25519::scalarmult(
    std::span<uint8_t, KEY_SIZE> output,
    std::span<const uint8_t, KEY_SIZE> secret,
    std::span<const uint8_t, KEY_SIZE> basepoint) noexcept 
{
    // Clamp the scalar
    uint8_t e[32];
    std::memcpy(e, secret.data(), 32);
    e[0]  &= 248;
    e[31] &= 127;
    e[31] |= 64;

    Fe x1, x2, z2, x3, z3, t0, t1;
    fe_frombytes(x1, basepoint);
    fe_1(x2);
    fe_0(z2);
    x3 = x1;
    fe_1(z3);

    uint8_t swap = 0;

    // Montgomery Ladder over Curve25519
    for (int pos = 254; pos >= 0; --pos) {
        uint8_t b = (e[pos / 8] >> (pos & 7)) & 1;
        swap ^= b;
        fe_cswap(x2, x3, swap);
        fe_cswap(z2, z3, swap);
        swap = b;

        // Differential Addition and Doubling
        fe_sub(t0, x3, z3); 
        fe_sub(t1, x2, z2);
        fe_add(x2, x2, z2);
        fe_add(z2, x3, z3);
        fe_mul(z3, t0, x2);
        fe_mul(z2, z2, t1);
        fe_sq(t0, t1);
        fe_sq(t1, x2);
        fe_add(x3, z3, z2);
        fe_sub(z2, z3, z2);
        fe_mul(x2, t1, t0);
        fe_sub(t1, t1, t0);
        fe_sq(z2, z2);
        fe_mul121666(z3, t1);
        fe_sq(x3, x3);
        fe_add(t0, t0, z3);
        fe_mul(z3, x1, z2);
        fe_mul(z2, t1, t0);
    }

    fe_cswap(x2, x3, swap);
    fe_cswap(z2, z3, swap);

    fe_invert(z2, z2);
    fe_mul(x2, x2, z2);
    fe_tobytes(output, x2);
}

void Curve25519::generate_public_key(
    std::span<uint8_t, KEY_SIZE> public_key_out,
    std::span<const uint8_t, KEY_SIZE> secret) noexcept 
{
    uint8_t basepoint[32] = {9}; // u=9 is the curve25519 base point
    scalarmult(public_key_out, secret, basepoint);
}

} // namespace nit::crypto::osnova
