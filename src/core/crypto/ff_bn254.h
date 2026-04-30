#pragma once
#include <cstdint>

namespace nit::crypto::osnova {

// 256-bit unsigned integer for cryptographic evaluation
struct U256 {
    uint64_t w[4];
    
    bool operator==(const U256& other) const;
    bool operator!=(const U256& other) const { return !(*this == other); }
    
    void add(const U256& a, const U256& b);
    void sub(const U256& a, const U256& b);
    void mul(const U256& a, const U256& b, uint64_t out[8]);
};

// Represents an element in the prime field F_q for BN254
// q = 21888242871839275222246405745257275088696311157297823662689037894645226208583
class Fr_BN254 {
public:
    U256 value;

    Fr_BN254();
    explicit Fr_BN254(uint64_t v);
    
    static const U256 MODULUS;
    static const uint64_t INV; // -q^(-1) mod 2^64

    void add_mod(const Fr_BN254& other);
    void sub_mod(const Fr_BN254& other);
    void mul_mod(const Fr_BN254& other); // Montgomery multiplication
    void inv(); // Modular inverse (Fermat's Little Theorem)
};

} // namespace nit::crypto::osnova
