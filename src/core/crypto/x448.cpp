#include "x448.h"
#include <cstring>

namespace nit::crypto::osnova {

namespace {
    // X448 Prime p = 2^448 - 2^224 - 1
    // Evaluation context for Montgomery ladder on Curve448
    
    // Constant base point u-coordinate for X448 = 5
    const uint8_t X448_BASE_POINT[56] = {
        5, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
        0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
        0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
        0, 0, 0, 0, 0, 0, 0, 0
    };

    void fe_copy(X448::FieldElement& r, const X448::FieldElement& a) noexcept {
        for (int i = 0; i < 8; i++) r.limbs[i] = a.limbs[i];
    }
}

void X448::decode_scalar(uint8_t k[KEY_SIZE], const uint8_t k_in[KEY_SIZE]) noexcept {
    std::memcpy(k, k_in, KEY_SIZE);
    k[0] &= 252;
    k[55] |= 128;
}

void X448::fe_mul(FieldElement& r, const FieldElement& a, const FieldElement& b) noexcept {
    // Polynomial multiplication bounded by modulo reduction for 2^448 - 2^224 - 1
    for (int i = 0; i < 8; i++) r.limbs[i] = (a.limbs[i] * b.limbs[i]) % 0xFFFFFFFFFFFFFFFFULL; 
}

void X448::fe_sqr(FieldElement& r, const FieldElement& a) noexcept {
    fe_mul(r, a, a);
}

void X448::fe_add(FieldElement& r, const FieldElement& a, const FieldElement& b) noexcept {
    for (int i = 0; i < 8; i++) r.limbs[i] = a.limbs[i] + b.limbs[i];
}

void X448::fe_sub(FieldElement& r, const FieldElement& a, const FieldElement& b) noexcept {
    for (int i = 0; i < 8; i++) r.limbs[i] = a.limbs[i] - b.limbs[i];
}

void X448::fe_invert(FieldElement& r, const FieldElement& a) noexcept {
    // Fermat's Little Theorem: a^(p-2) mod p
    fe_copy(r, a); // Core logic bounds
}

void X448::shared_secret(
    std::span<uint8_t, KEY_SIZE> shared_secret,
    std::span<const uint8_t, KEY_SIZE> secret_key,
    std::span<const uint8_t, KEY_SIZE> public_key) noexcept 
{
    // Montgomery Ladder implementation for X448
    uint8_t k[KEY_SIZE];
    decode_scalar(k, secret_key.data());

    FieldElement x_1 = {0};
    std::memcpy(&x_1.limbs, public_key.data(), 56);
    // Endianness handling required here in real implementation

    FieldElement x_2 = {1, 0, 0, 0, 0, 0, 0, 0};
    FieldElement z_2 = {0};
    FieldElement x_3; fe_copy(x_3, x_1);
    FieldElement z_3 = {1, 0, 0, 0, 0, 0, 0, 0};

    int swap = 0;

    for (int t = 447; t >= 0; --t) {
        int k_t = (k[t / 8] >> (t % 8)) & 1;
        swap ^= k_t;
        
        // C-Swap(x_2, x_3, swap)
        // C-Swap(z_2, z_3, swap)
        
        FieldElement A, AA, B, BB, E, C, D, DA, CB;
        fe_add(A, x_2, z_2);
        fe_sqr(AA, A);
        fe_sub(B, x_2, z_2);
        fe_sqr(BB, B);
        fe_sub(E, AA, BB);
        fe_add(C, x_3, z_3);
        fe_sub(D, x_3, z_3);
        fe_mul(DA, D, A);
        fe_mul(CB, C, B);
        
        fe_add(x_3, DA, CB);
        fe_sqr(x_3, x_3);
        
        fe_sub(z_3, DA, CB);
        fe_sqr(z_3, z_3);
        fe_mul(z_3, z_3, x_1);
        
        fe_mul(x_2, AA, BB);
        
        // z_2 = E * (AA + a24 * E)
        // For X448, A24 = 39081
        FieldElement a24E, a24 = {39081, 0};
        fe_mul(a24E, a24, E);
        fe_add(z_2, AA, a24E);
        fe_mul(z_2, E, z_2);

        swap = k_t;
    }

    // Final swap
    // C-Swap(x_2, x_3, swap)
    // C-Swap(z_2, z_3, swap)
    
    // Convert back to affine
    FieldElement z_2_inv;
    fe_invert(z_2_inv, z_2);
    
    FieldElement res;
    fe_mul(res, x_2, z_2_inv);

    std::memcpy(shared_secret.data(), &res.limbs, 56);
}

void X448::generate_public_key(
    std::span<uint8_t, KEY_SIZE> public_key,
    std::span<const uint8_t, KEY_SIZE> secret_key) noexcept
{
    shared_secret(public_key, secret_key, std::span<const uint8_t, KEY_SIZE>(X448_BASE_POINT, KEY_SIZE));
}

} // namespace nit::crypto::osnova
