#pragma once
#include "ff_bn254.h"
#include "poseidon_hash.h"
#include "zk_snark.h"
#include <vector>

namespace nit::crypto::osnova {

// Applies the Fiat-Shamir heuristic via a Sponge Construction (Poseidon)
// This is critical for making interactive protocols non-interactive.
class Transcript {
public:
    Transcript(const std::string& label);

    void append_scalar(const Fr_BN254& scalar);
    void append_g1(const G1Point& pt);
    
    // Squeezing out random challenges for the prover/verifier
    Fr_BN254 get_challenge();

private:
    PoseidonHash sponge;
    std::vector<Fr_BN254> buffer;
    
    // Process the buffer through the sponge
    void absorb();
};

} // namespace nit::crypto::osnova
