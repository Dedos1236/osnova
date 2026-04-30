#pragma once

#include <vector>
#include <string>
#include <cstdint>

namespace nit::crypto::osnova {

/**
 * @brief Paillier Cryptosystem - Partially Homomorphic Encryption.
 * 
 * Allows the server to compute the addition of two encrypted messages 
 * WITHOUT needing to decrypt them. Used in OSNOVA for spam scoring and 
 * network telemetry aggregation where the server is untrusted.
 */
class Paillier {
public:
    struct KeyPair {
        std::vector<uint8_t> public_key_n;
        std::vector<uint8_t> private_key_lambda; // Carmichael's function lcm(p-1, q-1)
        std::vector<uint8_t> private_key_mu;
    };

    /**
     * @brief Generate an RSA-like keypair for Paillier.
     */
    static KeyPair generate_keypair();

    /**
     * @brief Encrypt a plain 64-bit integer into a homomorphically addable ciphertext.
     */
    static std::vector<uint8_t> encrypt(uint64_t plaintext, const std::vector<uint8_t>& public_key_n);

    /**
     * @brief Homomorphically add two ciphertexts together (C1 * C2 mod n^2).
     * The result, when decrypted, will yield exactly (M1 + M2).
     */
    static std::vector<uint8_t> homomorphic_add(
        const std::vector<uint8_t>& ciphertext_1,
        const std::vector<uint8_t>& ciphertext_2,
        const std::vector<uint8_t>& public_key_n);

    /**
     * @brief Decrypt back to a standard integer.
     */
    static uint64_t decrypt(
        const std::vector<uint8_t>& ciphertext,
        const std::vector<uint8_t>& public_key_n,
        const std::vector<uint8_t>& private_key_lambda,
        const std::vector<uint8_t>& private_key_mu);
};

} // namespace nit::crypto::osnova
