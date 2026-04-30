#pragma once

#include "plonk_arithmetization.h"
#include "kzg_commitment.h"
#include "fiat_shamir_transcript.h"
#include "polynomial.h"
#include <vector>

namespace nit::crypto::osnova {

class PlonkProver {
public:
    struct ProvingKey {
        uint32_t n;
        uint32_t l;
        
        // Polynomial representations of selectors
        Polynomial qm_poly;
        Polynomial ql_poly;
        Polynomial qr_poly;
        Polynomial qo_poly;
        Polynomial qc_poly;
        
        // Polynomial representations of permutations
        Polynomial s1_poly;
        Polynomial s2_poly;
        Polynomial s3_poly;

        // Domain points
        std::vector<Fr_BN254> domain;
        
        // Constants used in evaluation (e.g., domain generator omega)
        Fr_BN254 k1;
        Fr_BN254 k2;
        Fr_BN254 omega;
    };

    static PlonkProof prove(const KZG10Commitment::SRS& srs,
                            const ProvingKey& pk,
                            const PlonkCircuit& circuit, 
                            const std::vector<Fr_BN254>& full_assignment,
                            const std::vector<Fr_BN254>& public_inputs);

private:
    static Polynomial generate_wire_polynomial(const std::vector<Fr_BN254>& assignments, const std::vector<uint32_t>& wire_indices, const ProvingKey& pk);
    static Polynomial quotient_polynomial(const ProvingKey& pk, const Polynomial& a, const Polynomial& b, const Polynomial& c, const Polynomial& z, const Fr_BN254& alpha, const Fr_BN254& beta, const Fr_BN254& gamma, const std::vector<Fr_BN254>& public_inputs);
};

} // namespace nit::crypto::osnova
