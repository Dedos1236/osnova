#pragma once
#include <vector>
#include <cstdint>
#include <map>
#include "ff_bn254.h"

namespace nit::crypto::osnova {

// Represents a linear combination of variables: sum(c_i * v_i)
struct LinearCombination {
    // Map of variable ID to coefficient
    std::map<uint32_t, Fr_BN254> terms;
    
    void add_term(uint32_t var_id, const Fr_BN254& coeff);
    Fr_BN254 evaluate(const std::vector<Fr_BN254>& assignment) const;
};

// R1CS Constraint: A * B = C
struct R1CSConstraint {
    LinearCombination a;
    LinearCombination b;
    LinearCombination c;
    
    bool is_satisfied(const std::vector<Fr_BN254>& assignment) const;
};

class R1CSSystem {
public:
    uint32_t num_variables;
    uint32_t num_public_inputs;
    std::vector<R1CSConstraint> constraints;

    R1CSSystem(uint32_t num_pub=0);

    uint32_t allocate_variable();
    void add_constraint(const R1CSConstraint& constraint);
    
    // Verify an assignment
    bool is_satisfied(const std::vector<Fr_BN254>& assignment) const;
};

} // namespace nit::crypto::osnova
