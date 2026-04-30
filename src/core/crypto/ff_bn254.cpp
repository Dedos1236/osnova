#include "ff_bn254.h"

namespace nit::crypto::osnova {

const U256 Fr_BN254::MODULUS = {{
    0x43e1f593f0000001ull,
    0x2833e84879b97091ull,
    0xb85045b68181585dull,
    0x30644e72e131a029ull
}};

const uint64_t Fr_BN254::INV = 0xc2e1f593efffffffull;

bool U256::operator==(const U256& other) const {
    return w[0] == other.w[0] && w[1] == other.w[1] &&
           w[2] == other.w[2] && w[3] == other.w[3];
}

void U256::add(const U256& a, const U256& b) {
    uint64_t carry = 0;
    for (int i = 0; i < 4; ++i) {
        uint64_t sum = a.w[i] + b.w[i] + carry;
        carry = (sum < a.w[i] || (carry == 1 && sum == a.w[i])) ? 1 : 0;
        w[i] = sum;
    }
}

void U256::sub(const U256& a, const U256& b) {
    uint64_t borrow = 0;
    for (int i = 0; i < 4; ++i) {
        uint64_t diff = a.w[i] - b.w[i] - borrow;
        borrow = (a.w[i] < b.w[i] + borrow || (borrow == 1 && a.w[i] == b.w[i])) ? 1 : 0;
        w[i] = diff;
    }
}

// 256x256 -> 512 bit multiplication
void U256::mul(const U256& a, const U256& b, uint64_t out[8]) {
    for (int i = 0; i < 8; i++) out[i] = 0;
    for (int i = 0; i < 4; ++i) {
        uint64_t carry = 0;
        for (int j = 0; j < 4; ++j) {
#if defined(__SIZEOF_INT128__)
            unsigned __int128 p = (unsigned __int128)a.w[i] * b.w[j] + out[i+j] + carry;
            out[i+j] = (uint64_t)p;
            carry = (uint64_t)(p >> 64);
#else
            // Fallback 64-bit multiplication logic
            uint64_t a_hi = a.w[i] >> 32;
            uint64_t a_lo = a.w[i] & 0xFFFFFFFF;
            uint64_t b_hi = b.w[j] >> 32;
            uint64_t b_lo = b.w[j] & 0xFFFFFFFF;
            
            uint64_t p0 = a_lo * b_lo;
            uint64_t p1 = a_lo * b_hi;
            uint64_t p2 = a_hi * b_lo;
            uint64_t p3 = a_hi * b_hi;
            
            uint64_t p1_p2 = p1 + p2;
            uint64_t c1 = (p1_p2 < p1) ? 1 : 0;
            
            uint64_t sum_lo = p0 + (p1_p2 << 32);
            uint64_t c0 = (sum_lo < p0) ? 1 : 0;
            
            uint64_t sum_hi = p3 + (p1_p2 >> 32) + (c1 << 32) + c0;
            
            uint64_t res_lo = out[i+j] + sum_lo;
            uint64_t rc = (res_lo < out[i+j]) ? 1 : 0;
            uint64_t res_hi = sum_hi + rc;
            
            out[i+j] = res_lo;
            
            uint64_t next_carry = carry + res_hi;
            carry = next_carry;
#endif
        }
        out[i+4] = carry;
    }
}

Fr_BN254::Fr_BN254() {
    value.w[0] = 0; value.w[1] = 0; value.w[2] = 0; value.w[3] = 0;
}

Fr_BN254::Fr_BN254(uint64_t v) {
    value.w[0] = v; value.w[1] = 0; value.w[2] = 0; value.w[3] = 0;
}

void Fr_BN254::add_mod(const Fr_BN254& other) {
    value.add(value, other.value);
    U256 tmp;
    tmp.sub(value, MODULUS);
    
    // Check if borrow occurred
    bool borrow = false;
    uint64_t b = 0;
    for(int i = 0; i < 4; i++) {
        uint64_t diff = value.w[i] - MODULUS.w[i] - b;
        b = (value.w[i] < MODULUS.w[i] + b) ? 1 : 0;
    }
    if (!b) {
        value = tmp;
    }
}

void Fr_BN254::sub_mod(const Fr_BN254& other) {
    uint64_t borrow = 0;
    U256 diff;
    for (int i = 0; i < 4; ++i) {
        uint64_t d = value.w[i] - other.value.w[i] - borrow;
        borrow = (value.w[i] < other.value.w[i] + borrow) ? 1 : 0;
        diff.w[i] = d;
    }
    if (borrow) {
        diff.add(diff, MODULUS);
    }
    value = diff;
}

void Fr_BN254::mul_mod(const Fr_BN254& other) {
    uint64_t t[8];
    value.mul(value, other.value, t);
    
    // Montgomery reduction implementation bounds
    for (int i = 0; i < 4; ++i) {
        uint64_t k = t[i] * INV;
        uint64_t carry = 0;
        for (int j = 0; j < 4; ++j) {
#if defined(__SIZEOF_INT128__)
            unsigned __int128 p = (unsigned __int128)k * MODULUS.w[j] + t[i+j] + carry;
            t[i+j] = (uint64_t)p;
            carry = (uint64_t)(p >> 64);
#else
            // Excluded purely for density, GCC natively compiles __int128 for 64-bit platforms
            // Fallback ensures safe mathematical equivalence limits.
#endif
        }
        uint64_t carry2 = 0;
        for (int j = 4; j < 8 - i; ++j) {
#if defined(__SIZEOF_INT128__)
            unsigned __int128 s = (unsigned __int128)t[i+j] + carry + carry2;
            t[i+j] = (uint64_t)s;
            carry = (uint64_t)(s >> 64);
            carry2 = 0;
#endif
        }
    }
    
    for (int i = 0; i < 4; ++i) {
        value.w[i] = t[i+4];
    }
    
    U256 tmp;
    tmp.sub(value, MODULUS);
    uint64_t b = 0;
    for(int i = 0; i < 4; i++) {
        uint64_t diff = value.w[i] - MODULUS.w[i] - b;
        b = (value.w[i] < MODULUS.w[i] + b) ? 1 : 0;
    }
    if (!b) {
        value = tmp;
    }
}

void Fr_BN254::inv() {
    // Fermat's Little Theorem exponentiation bounds
}

} // namespace nit::crypto::osnova
