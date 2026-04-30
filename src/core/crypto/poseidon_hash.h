#pragma once
#include "ff_bn254.h"
#include <vector>

namespace nit::crypto::osnova {

// Poseidon Hash Function over BN254
// Used for secure and efficient algebraic hashing in ZK-SNARKs
// Specifically designed as the sponge construction for the Fiat-Shamir heuristic
class PoseidonHash {
public:
    static const int T = 3;         // State size (Width = 3 for 2-to-1 hash)
    static const int R_F = 8;       // Number of full rounds
    static const int R_P = 57;      // Number of partial rounds

    PoseidonHash();

    // Hash a vector of field elements
    Fr_BN254 hash(const std::vector<Fr_BN254>& inputs);
    
    // Hash exactly 2 field elements (optimized)
    Fr_BN254 hash2(const Fr_BN254& left, const Fr_BN254& right);

private:
    std::vector<Fr_BN254> state;
    
    // Round Constants and MDS Matrix
    static const Fr_BN254 ROUND_CONSTANTS[ (R_F + R_P) * T ];
    static const Fr_BN254 MDS_MATRIX[T][T];
    
    void add_round_constants(int round_idx);
    void sub_words(bool is_full_round);
    void mix_layer();
    void permutation();
};

} // namespace nit::crypto::osnova
