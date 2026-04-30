#pragma once

#include <vector>
#include <cstdint>
#include <span>

namespace nit::crypto::osnova {

/**
 * @brief Kyber Post-Quantum Key Encapsulation Mechanism (KEM).
 * Crystal-Kyber is standard for PQC key exchange. 
 * OSNOVA uses Kyber to future-proof the Double Ratchet and Handshake against quantum adversaries 
 * running Shor's algorithm.
 */
class PqKyber {
public:
    static constexpr size_t PUBLIC_KEY_SIZE = 800;  // Kyber-512 params
    static constexpr size_t PRIVATE_KEY_SIZE = 1632;
    static constexpr size_t CIPHERTEXT_SIZE = 768;
    static constexpr size_t SHARED_SECRET_SIZE = 32;

    struct KeyPair {
        std::vector<uint8_t> public_key;
        std::vector<uint8_t> private_key;
    };

    /**
     * @brief Generate Kyber Keypair.
     */
    static KeyPair generate_keypair();

    /**
     * @brief Encapsulate a shared secret against a target public key.
     * @param public_key Receiver's PQ public key.
     * @param out_ciphertext The encapsulated ciphertext to send to the receiver.
     * @param out_shared_secret The 32-byte shared secret for AEAD.
     * @return true on success.
     */
    static bool encapsulate(
        std::span<const uint8_t> public_key,
        std::vector<uint8_t>& out_ciphertext,
        std::vector<uint8_t>& out_shared_secret);

    /**
     * @brief Decapsulate a shared secret from a received ciphertext.
     * @param private_key Receiver's PQ private key.
     * @param ciphertext The received ciphertext.
     * @param out_shared_secret The resulting 32-byte shared secret.
     * @return true on success.
     */
    static bool decapsulate(
        std::span<const uint8_t> private_key,
        std::span<const uint8_t> ciphertext,
        std::vector<uint8_t>& out_shared_secret);
};

} // namespace nit::crypto::osnova
