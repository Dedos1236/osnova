#pragma once
#include "plonk_arithmetization.h"
#include "kzg_commitment.h"
#include "fiat_shamir_transcript.h"
#include <vector>

namespace nit::crypto::osnova {

class PlonkVerifier {
public:
    // Plonk Verification Key contains commitments to selector and permutation polynomials
    struct VerificationKey {
        uint32_t n; // Circuit size
        uint32_t l; // Number of public inputs
        
        // Selector commitments
        G1Point qm_comm;
        G1Point ql_comm;
        G1Point qr_comm;
        G1Point qo_comm;
        G1Point qc_comm;
        
        // Permutation commitments
        G1Point s1_comm;
        G1Point s2_comm;
        G1Point s3_comm;
        
        // Constants used in evaluation (e.g., domain generator omega)
        Fr_BN254 k1;
        Fr_BN254 k2;
        Fr_BN254 omega;
    };

    static bool verify(const KZG10Commitment::SRS& srs, 
                       const VerificationKey& vk, 
                       const PlonkProof& proof, 
                       const std::vector<Fr_BN254>& public_inputs);
};

} // namespace nit::crypto::osnova
