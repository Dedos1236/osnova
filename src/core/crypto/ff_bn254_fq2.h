#pragma once
#include "ff_bn254.h"

namespace nit::crypto::osnova {

// Represents an element in the quadratic extension field F_q^2
// F_q^2 is constructed as F_q[u] / (u^2 + 1) since p = 3 mod 4.
// Element: c0 + c1 * u
class Fq2_BN254 {
public:
    Fr_BN254 c0;
    Fr_BN254 c1;

    Fq2_BN254();
    Fq2_BN254(const Fr_BN254& c0, const Fr_BN254& c1);
    explicit Fq2_BN254(uint64_t v);

    void add(const Fq2_BN254& other);
    void sub(const Fq2_BN254& other);
    void mul(const Fq2_BN254& other);
    
    // Multiply by a scalar in F_q
    void mul_scalar(const Fr_BN254& scalar);

    void square();
    void inv();
    
    // Frobenius automorphism: a + bu -> a - bu
    void conjugate();

    bool is_zero() const;
    bool operator==(const Fq2_BN254& other) const;
    bool operator!=(const Fq2_BN254& other) const { return !(*this == other); }
};

} // namespace nit::crypto::osnova
