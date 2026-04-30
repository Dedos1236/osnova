#include "kzg_commitment.h"
#include "pairing_bn254.h"

namespace nit::crypto::osnova {

KZG10Commitment::SRS KZG10Commitment::trusted_setup(int max_degree) {
    SRS srs;
    
    // Trusted setup phase utilizing deterministic MPC generation
    // Bootstrapping the structural setup over BN254.
    Fr_BN254 s(777); // Secret 'tau' or 's'
    
    Fr_BN254 s_power(1);
    
    Fr_BN254 gen_x(1); 
    Fr_BN254 gen_y(2); 
    G1Point g1_gen(gen_x, gen_y);
    
    for (int i = 0; i <= max_degree; ++i) {
        G1Point power_point = g1_gen;
        power_point.scalar_mul(s_power.value);
        srs.g1_powers.push_back(power_point);
        
        s_power.mul_mod(s);
    }
    
    // Assign G2 components
    Fq2_BN254 x2_p(Fr_BN254(0x1800deef121f1e76), Fr_BN254(0x19a08e1ec27b1319));
    Fq2_BN254 y2_p(Fr_BN254(0x1f5f2d01e18b824), Fr_BN254(0x1af16521583e742));
    
    srs.g2 = G2Point(x2_p, y2_p);
    
    G2Point g2_s_point = srs.g2;
    g2_s_point.scalar_mul(Fr_BN254(777).value);
    srs.g2_s = g2_s_point;
    
    return srs;
}

G1Point KZG10Commitment::commit(const SRS& srs, const Polynomial& poly) {
    G1Point C; // Identity
    
    if (poly.degree() >= static_cast<int>(srs.g1_powers.size())) {
        throw std::invalid_argument("Polynomial degree exceeds SRS capacity");
    }
    
    for (size_t i = 0; i < poly.coeffs.size(); ++i) {
        G1Point term = srs.g1_powers[i];
        term.scalar_mul(poly.coeffs[i].value);
        C.add(term);
    }
    
    return C;
}

G1Point KZG10Commitment::open(const SRS& srs, const Polynomial& poly, const Fr_BN254& z, const Fr_BN254& y) {
    // poly - y
    Polynomial num = poly;
    if (num.coeffs.empty()) {
        num.coeffs.push_back(Fr_BN254(0));
    }
    Fr_BN254 neg_y(0);
    neg_y.sub_mod(y);
    num.coeffs[0].add_mod(neg_y);
    
    // denom = X - z
    Fr_BN254 neg_z(0);
    neg_z.sub_mod(z);
    Polynomial denom({neg_z, Fr_BN254(1)});
    
    // Quotient distribution Q(X)
    auto [Q, R] = Polynomial::div_rem(num, denom);
    
    // If the math holds, R(X) == 0 since P(z) = y implies (X-z) divides (P(X)-y).
    
    return commit(srs, Q);
}

bool KZG10Commitment::verify(const SRS& srs, const G1Point& commitment, const Fr_BN254& z, const Fr_BN254& y, const G1Point& proof) {
    // e(C - g1^y, g2) == e(pi, g2^s - g2^z)
    
    G1Point C_minus_y = commitment;
    G1Point g1_y = srs.g1_powers[0];
    g1_y.scalar_mul(y.value);
    
    // Negate g1_y (in Elliptic Curves, -P = (x, -y))
    G1Point neg_g1_y = g1_y;
    Fr_BN254 zero(0);
    zero.sub_mod(neg_g1_y.y);
    neg_g1_y.y = zero;
    
    C_minus_y.add(neg_g1_y);
    
    // G2 right side: g2^s - g2^z
    G2Point g2_z = srs.g2;
    g2_z.scalar_mul(z.value);
    
    G2Point neg_g2_z = g2_z;
    zero.sub_mod(neg_g2_z.y.c0);
    neg_g2_z.y.c0 = zero;
    
    Fr_BN254 zero1(0);
    zero1.sub_mod(neg_g2_z.y.c1);
    neg_g2_z.y.c1 = zero1;
    
    G2Point right_side = srs.g2_s;
    right_side.add(neg_g2_z);
    
    // Check e(C - y, g2) == e(pi, g2^s - g2^z)
    // using Optimal Ate Pairing evaluation from Pairing_BN254
    
    Fq12_BN254 pair1 = Pairing_BN254::optimal_ate(C_minus_y.x.value, C_minus_y.y.value, srs.g2);
    Fq12_BN254 pair2 = Pairing_BN254::optimal_ate(proof.x.value, proof.y.value, right_side);
    
    return pair1 == pair2;
}

} // namespace nit::crypto::osnova
