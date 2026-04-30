#pragma once

#include <vector>
#include <string>
#include <cstdint>
#include <span>

namespace nit::crypto::osnova {

/**
 * @brief Zero-Knowledge Succinct Non-Interactive Argument of Knowledge (zk-SNARK).
 *
 * Groundbreaking primitive natively integrated into OSNOVA.
 * Allows a client to cryptographically PROVE a statement (like "I belong to Group X" 
 * or "I am over 18" or "I am an administrator") to the server without REVEALING 
 * the underlying credential data whatsoever.
 */
class ZkSnark {
public:
    struct ProvingKey {
        std::vector<uint8_t> data;
    };

    struct VerificationKey {
        std::vector<uint8_t> data;
    };

    struct Proof {
        std::vector<uint8_t> data;
    };

    /**
     * @brief Setup the trusted circuit parameters for this application statement.
     */
    static void generate_circuit_keys(ProvingKey& out_pk, VerificationKey& out_vk);

    /**
     * @brief Generate a zk-SNARK proof given public inputs and highly secret witness.
     */
    static Proof prove(
        const ProvingKey& pk,
        const std::vector<uint8_t>& public_inputs,
        const std::vector<uint8_t>& secret_witness);

    /**
     * @brief The server verifies the proof using only the public inputs and verification key in O(1).
     */
    static bool verify(
        const VerificationKey& vk,
        const Proof& proof,
        const std::vector<uint8_t>& public_inputs);
};

} // namespace nit::crypto::osnova
