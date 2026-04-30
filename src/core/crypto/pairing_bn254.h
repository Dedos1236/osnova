#pragma once
#include "ff_bn254_fq2.h"
#include "zk_snark.h" // for G1Point (need to define G1Point either in zk_snark.h or here, wait, G1Point is currently inside zk_snark.cpp. Lets move it to a common header, but for now I can redefine or just declare).

namespace nit::crypto::osnova {

// G2 Point on BN254 over Fq2: y^2 = x^3 + 3/(9+u)
struct G2Point {
    Fq2_BN254 x;
    Fq2_BN254 y;
    bool infinity;

    G2Point();
    G2Point(const Fq2_BN254& x_in, const Fq2_BN254& y_in);

    void add(const G2Point& other);
    void double_point();
    void scalar_mul(const U256& scalar);
};

// Represents an element in F_q^12.
// F_q^12 is constructed as F_q^2[w] / (w^6 - xi) where xi = 9 + u
class Fq12_BN254 {
public:
    Fq2_BN254 c0;
    Fq2_BN254 c1;
    Fq2_BN254 c2;
    Fq2_BN254 c3;
    Fq2_BN254 c4;
    Fq2_BN254 c5;

    Fq12_BN254();
    
    void add(const Fq12_BN254& other);
    void sub(const Fq12_BN254& other);
    void mul(const Fq12_BN254& other);
    void square();
    void inv();
    
    // Frobenius automorphisms
    void frobenius_map(int power);

    bool is_one() const;
    bool operator==(const Fq12_BN254& other) const;
};

// Computes the Optimal Ate Pairing for BN254:
// maps a G1Point and a G2Point to an element in Fq12
// e: G1 x G2 -> Fq12
class Pairing_BN254 {
public:
    // P is in G1, Q is in G2
    static Fq12_BN254 optimal_ate(const U256& px, const U256& py, const G2Point& Q);
    
    // Verifies the pairing equality: e(A, B) == e(C, D)
    static bool verify_pairing(const U256& ax, const U256& ay, const G2Point& B, 
                               const U256& cx, const U256& cy, const G2Point& D);
                               
    // Computes Miller Loop
    static Fq12_BN254 miller_loop(const U256& px, const U256& py, const G2Point& Q);
    // Final Exponentiation
    static Fq12_BN254 final_exponentiation(const Fq12_BN254& f);
};

} // namespace nit::crypto::osnova
