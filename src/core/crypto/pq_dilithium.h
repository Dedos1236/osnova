#pragma once

#include <vector>
#include <cstdint>
#include <span>

namespace nit::crypto::osnova {

/**
 * @brief Crystals-Dilithium Post-Quantum Digital Signature Algorithm.
 * Offers strong security against quantum adversaries.
 * Used in OSNOVA for identity verification and handshake authentication.
 */
class PqDilithium {
public:
    static constexpr size_t PUBLIC_KEY_SIZE = 1312; // Dilithium2
    static constexpr size_t PRIVATE_KEY_SIZE = 2528;
    static constexpr size_t SIGNATURE_SIZE = 2420;

    struct KeyPair {
        std::vector<uint8_t> public_key;
        std::vector<uint8_t> private_key;
    };

    /**
     * @brief Generate Dilithium Keypair.
     */
    static KeyPair generate_keypair();

    /**
     * @brief Sign a message using Dilithium.
     * @param signature Output buffer for the signature.
     * @param private_key Signer's PQ private key.
     * @param message Message to sign.
     * @return true on success.
     */
    static bool sign(
        std::vector<uint8_t>& signature,
        std::span<const uint8_t> private_key,
        std::span<const uint8_t> message);

    /**
     * @brief Verify a Dilithium signature.
     * @param public_key Signer's PQ public key.
     * @param message Signed message.
     * @param signature The signature to verify.
     * @return true if signature is valid.
     */
    static bool verify(
        std::span<const uint8_t> public_key,
        std::span<const uint8_t> message,
        std::span<const uint8_t> signature);
};

} // namespace nit::crypto::osnova
