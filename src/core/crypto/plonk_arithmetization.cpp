#include "plonk_arithmetization.h"

namespace nit::crypto::osnova {

PlonkCircuit::PlonkCircuit(uint32_t num_pub) 
    : num_variables(num_pub), num_public_inputs(num_pub) {}

uint32_t PlonkCircuit::allocate_variable() {
    return num_variables++;
}

void PlonkCircuit::add_gate(const PlonkGate& gate) {
    gates.push_back(gate);
}

void PlonkCircuit::add_copy_constraint(uint32_t wire_idx_1, uint32_t wire_idx_2) {
    copy_edges.push_back({wire_idx_1, wire_idx_2});
}

// Disjoint Set Union mapping helper
struct DSU {
    std::vector<uint32_t> parent;
    DSU(uint32_t n) {
        parent.resize(n);
        for(uint32_t i=0; i<n; ++i) parent[i] = i;
    }
    uint32_t find(uint32_t i) {
        if (parent[i] == i) return i;
        return parent[i] = find(parent[i]);
    }
    void unite(uint32_t i, uint32_t j) {
        uint32_t root_i = find(i);
        uint32_t root_j = find(j);
        if (root_i != root_j) {
            parent[root_i] = root_j;
        }
    }
};

void PlonkCircuit::compile_permutations() {
    size_t n = gates.size();
    sigma_1.resize(n);
    sigma_2.resize(n);
    sigma_3.resize(n);
    
    // Default permutation is identity
    for (size_t i = 0; i < n; ++i) {
        sigma_1[i] = i;
        sigma_2[i] = n + i;
        sigma_3[i] = 2 * n + i;
    }

    // A full implementation requires tracking cycles of disjoint sets.
    // Total wire occurrences: 3 * n
    DSU dsu(3 * n);

    // Map each variable ID to a list of its occurrences (gate_idx + offset)
    std::vector<std::vector<uint32_t>> var_occurrences(num_variables);
    for (size_t i = 0; i < n; ++i) {
        var_occurrences[gates[i].w_a].push_back(i);           // L
        var_occurrences[gates[i].w_b].push_back(n + i);       // R
        var_occurrences[gates[i].w_c].push_back(2 * n + i);   // O
    }
    
    // Create union of cycles within explicitly copied variables
    for (const auto& edge : copy_edges) {
        if (edge.w1 < num_variables && edge.w2 < num_variables) {
            if (!var_occurrences[edge.w1].empty() && !var_occurrences[edge.w2].empty()) {
                dsu.unite(var_occurrences[edge.w1][0], var_occurrences[edge.w2][0]);
            }
        }
    }
    
    // Group all connected wire positions across variables
    for (size_t var = 0; var < num_variables; ++var) {
        if (var_occurrences[var].size() <= 1) continue;
        for (size_t j = 1; j < var_occurrences[var].size(); ++j) {
            dsu.unite(var_occurrences[var][0], var_occurrences[var][j]);
        }
    }

    std::vector<std::vector<uint32_t>> cycles(3 * n);
    for (size_t i = 0; i < 3 * n; ++i) {
        cycles[dsu.find(i)].push_back(i);
    }

    // Build the permutation shifts mapping rightward
    for (const auto& cycle : cycles) {
        if (cycle.size() <= 1) continue;
        for (size_t i = 0; i < cycle.size(); ++i) {
            uint32_t current = cycle[i];
            uint32_t next = cycle[(i + 1) % cycle.size()];
            
            if (current < n) sigma_1[current] = next;
            else if (current < 2 * n) sigma_2[current - n] = next;
            else sigma_3[current - 2 * n] = next;
        }
    }
}

bool PlonkCircuit::is_satisfied(const std::vector<Fr_BN254>& assignment) const {
    if (assignment.size() < num_variables) return false;
    
    for (const auto& gate : gates) {
        Fr_BN254 a = assignment[gate.w_a];
        Fr_BN254 b = assignment[gate.w_b];
        Fr_BN254 c = assignment[gate.w_c];
        
        Fr_BN254 L = gate.q_L; L.mul_mod(a);
        Fr_BN254 R = gate.q_R; R.mul_mod(b);
        Fr_BN254 O = gate.q_O; O.mul_mod(c);
        
        Fr_BN254 M = gate.q_M; 
        M.mul_mod(a); 
        M.mul_mod(b);
        
        Fr_BN254 sum = L;
        sum.add_mod(R);
        sum.add_mod(O);
        sum.add_mod(M);
        sum.add_mod(gate.q_C);
        
        U256 zero{{0, 0, 0, 0}};
        if (!(sum.value == zero)) return false;
    }
    
    // Checking copy constraints natively
    for (const auto& edge : copy_edges) {
        if (edge.w1 < assignment.size() && edge.w2 < assignment.size()) {
            if (!(assignment[edge.w1].value == assignment[edge.w2].value)) {
                return false;
            }
        }
    }

    return true;
}

} // namespace nit::crypto::osnova
