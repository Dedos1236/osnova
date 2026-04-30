#pragma once
#include <vector>
#include <cstdint>
#include "ff_bn254.h"

namespace nit::crypto::osnova {

// PLONK Gate constraints
// q_L * a + q_R * b + q_O * c + q_M * (a * b) + q_C = 0
struct PlonkGate {
    Fr_BN254 q_L;
    Fr_BN254 q_R;
    Fr_BN254 q_O;
    Fr_BN254 q_M;
    Fr_BN254 q_C;
    
    uint32_t w_a;
    uint32_t w_b;
    uint32_t w_c;
};

class PlonkCircuit {
public:
    uint32_t num_variables;
    uint32_t num_public_inputs;
    std::vector<PlonkGate> gates;
    
    // Copy constraints defined as permutation cycles
    // mapping wire index to wire index across all gates.
    std::vector<uint32_t> sigma_1;
    std::vector<uint32_t> sigma_2;
    std::vector<uint32_t> sigma_3;

    PlonkCircuit(uint32_t num_pub=0);

    uint32_t allocate_variable();
    void add_gate(const PlonkGate& gate);
    
    // Wire up permutaions for copy constraints
    void add_copy_constraint(uint32_t wire_idx_1, uint32_t wire_idx_2);
    
    void compile_permutations();

    bool is_satisfied(const std::vector<Fr_BN254>& assignment) const;

private:
    // Internal struct to hold copy constraint edges
    struct CopyGraphEdge {
        uint32_t w1;
        uint32_t w2;
    };
    std::vector<CopyGraphEdge> copy_edges;
};

// Represents a PLONK proof containing polynomial commitments
struct PlonkProof {
    // Commitments to wire polynomials
    U256 a_comm[2];
    U256 b_comm[2];
    U256 c_comm[2];
    // Commitments to permutation polynomials
    U256 z_comm[2];
    // Commitments to quotient polynomial parts
    U256 t_lo_comm[2];
    U256 t_mid_comm[2];
    U256 t_hi_comm[2];
    
    // Proof evaluations
    Fr_BN254 a_eval;
    Fr_BN254 b_eval;
    Fr_BN254 c_eval;
    Fr_BN254 s1_eval;
    Fr_BN254 s2_eval;
    Fr_BN254 z_omega_eval;
    
    // Batched Opening proof
    U256 w_z_comm[2];
    U256 w_z_omega_comm[2];
};

} // namespace nit::crypto::osnova
