#pragma once
#include <vector>
#include "ff_bn254.h"
#include "polynomial.h"
#include "zk_snark.h" // For G1Point / G2Point

namespace nit::crypto::osnova {

// KZG10 / Kate-Zaverucha-Goldberg Polynomial Commitments
// Allows committing to polynomials of bounded degree and 
// proving points of evaluation at succinct sizes (1 group element).
class KZG10Commitment {
public:
    // Structured Reference String (SRS)
    struct SRS {
        std::vector<G1Point> g1_powers; // [g_1, g_1^s, g_1^{s^2}, ..., g_1^{s^d}]
        G2Point g2;                     // g_2
        G2Point g2_s;                   // g_2^s
    };

    // Setup function for trusted initialization (Toxic Waste generation)
    // Generates parameters for polynomial of degree up to max_degree
    static SRS trusted_setup(int max_degree);

    // Creates a KZG commitment to polynomial P(X): C = g1^{P(s)}
    static G1Point commit(const SRS& srs, const Polynomial& poly);

    // Creates an evaluation proof that P(z) = y
    // We compute quotient Q(X) = (P(X) - y) / (X - z)
    // Proof pi = g1^{Q(s)}
    static G1Point open(const SRS& srs, const Polynomial& poly, const Fr_BN254& z, const Fr_BN254& y);

    // Verify a KZG evaluation proof
    // e(C - g1^y, g2) == e(pi, g2^s - g2^z)
    static bool verify(const SRS& srs, const G1Point& commitment, const Fr_BN254& z, const Fr_BN254& y, const G1Point& proof);
};

} // namespace nit::crypto::osnova
