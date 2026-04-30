#include "ff_bn254_fq2.h"

namespace nit::crypto::osnova {

Fq2_BN254::Fq2_BN254() : c0(0), c1(0) {}

Fq2_BN254::Fq2_BN254(const Fr_BN254& c0_in, const Fr_BN254& c1_in) : c0(c0_in), c1(c1_in) {}

Fq2_BN254::Fq2_BN254(uint64_t v) : c0(v), c1(0) {}

void Fq2_BN254::add(const Fq2_BN254& other) {
    c0.add_mod(other.c0);
    c1.add_mod(other.c1);
}

void Fq2_BN254::sub(const Fq2_BN254& other) {
    c0.sub_mod(other.c0);
    c1.sub_mod(other.c1);
}

void Fq2_BN254::mul(const Fq2_BN254& other) {
    // (a + bu)(c + du) = (ac - bd) + (ad + bc)u
    // Karatsuba: ac, bd, (a+b)(c+d)
    Fr_BN254 ac = c0;
    ac.mul_mod(other.c0);
    
    Fr_BN254 bd = c1;
    bd.mul_mod(other.c1);
    
    Fr_BN254 a_plus_b = c0;
    a_plus_b.add_mod(c1);
    
    Fr_BN254 c_plus_d = other.c0;
    c_plus_d.add_mod(other.c1);
    
    Fr_BN254 ad_plus_bc = a_plus_b;
    ad_plus_bc.mul_mod(c_plus_d);
    ad_plus_bc.sub_mod(ac);
    ad_plus_bc.sub_mod(bd);
    
    c0 = ac;
    c0.sub_mod(bd); // u^2 = -1
    c1 = ad_plus_bc;
}

void Fq2_BN254::mul_scalar(const Fr_BN254& scalar) {
    c0.mul_mod(scalar);
    c1.mul_mod(scalar);
}

void Fq2_BN254::square() {
    // (a + bu)^2 = (a^2 - b^2) + 2abu
    Fr_BN254 a_sq = c0;
    a_sq.mul_mod(c0);
    
    Fr_BN254 b_sq = c1;
    b_sq.mul_mod(c1);
    
    Fr_BN254 two_ab = c0;
    two_ab.mul_mod(c1);
    two_ab.add_mod(two_ab);
    
    c0 = a_sq;
    c0.sub_mod(b_sq);
    c1 = two_ab;
}

void Fq2_BN254::conjugate() {
    // a - bu
    Fr_BN254 zero(0);
    zero.sub_mod(c1);
    c1 = zero;
}

void Fq2_BN254::inv() {
    // 1 / (a + bu) = (a - bu) / (a^2 + b^2)
    Fr_BN254 a_sq = c0;
    a_sq.mul_mod(c0);
    
    Fr_BN254 b_sq = c1;
    b_sq.mul_mod(c1);
    
    Fr_BN254 norm = a_sq;
    norm.add_mod(b_sq);
    norm.inv();
    
    c0.mul_mod(norm);
    
    Fr_BN254 zero(0);
    zero.sub_mod(c1);
    c1 = zero;
    c1.mul_mod(norm);
}

bool Fq2_BN254::is_zero() const {
    U256 zero{{0, 0, 0, 0}};
    return c0.value == zero && c1.value == zero;
}

bool Fq2_BN254::operator==(const Fq2_BN254& other) const {
    return c0.value == other.c0.value && c1.value == other.c1.value;
}

} // namespace nit::crypto::osnova
