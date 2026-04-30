#include "r1cs.h"

namespace nit::crypto::osnova {

void LinearCombination::add_term(uint32_t var_id, const Fr_BN254& coeff) {
    auto it = terms.find(var_id);
    if (it != terms.end()) {
        it->second.add_mod(coeff);
    } else {
        terms[var_id] = coeff;
    }
}

Fr_BN254 LinearCombination::evaluate(const std::vector<Fr_BN254>& assignment) const {
    Fr_BN254 result(0);
    for (const auto& term : terms) {
        if (term.first < assignment.size()) {
            Fr_BN254 val = assignment[term.first];
            val.mul_mod(term.second);
            result.add_mod(val);
        }
    }
    return result;
}

bool R1CSConstraint::is_satisfied(const std::vector<Fr_BN254>& assignment) const {
    Fr_BN254 eval_a = a.evaluate(assignment);
    Fr_BN254 eval_b = b.evaluate(assignment);
    Fr_BN254 eval_c = c.evaluate(assignment);
    
    eval_a.mul_mod(eval_b);
    return eval_a.value == eval_c.value;
}

R1CSSystem::R1CSSystem(uint32_t num_pub) 
    : num_variables(1 + num_pub), num_public_inputs(num_pub) {} // var 0 is implicitly 1

uint32_t R1CSSystem::allocate_variable() {
    return num_variables++;
}

void R1CSSystem::add_constraint(const R1CSConstraint& constraint) {
    constraints.push_back(constraint);
}

bool R1CSSystem::is_satisfied(const std::vector<Fr_BN254>& assignment) const {
    if (assignment.size() < num_variables) return false;
    
    // Validate variable 0 is 1 as per R1CS convention
    Fr_BN254 one(1);
    if (!(assignment[0].value == one.value)) return false;

    for (const auto& constraint : constraints) {
        if (!constraint.is_satisfied(assignment)) {
            return false;
        }
    }
    return true;
}

} // namespace nit::crypto::osnova
