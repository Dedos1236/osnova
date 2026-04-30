#pragma once

#include <cstdint>
#include <span>

namespace nit::crypto::osnova {

/**
 * @brief Simple Schnorr NIZK Proof (Non-Interactive Zero-Knowledge) over Curve25519.
 * Allows proving knowledge of a discrete logarithm (private key) without revealing it.
 */
class SchnorrZkp {
public:
    static constexpr size_t PROOF_SIZE = 64; // 32 bytes for R (public commitment), 32 bytes for s (response)

    /**
     * @brief Generate a ZKP of knowledge of 'secret'.
     * 
     * @param proof Output proof (64 bytes).
     * @param secret The scalar secret (32 bytes).
     * @param public_key The public key associated with the secret, to bind the proof.
     * @param context Application specific context string (optional binding).
     */
    static void prove(
        std::span<uint8_t, PROOF_SIZE> proof,
        std::span<const uint8_t, 32> secret,
        std::span<const uint8_t, 32> public_key,
        std::span<const uint8_t> context) noexcept;

    /**
     * @brief Verify a ZKP.
     * 
     * @param proof The generated proof (64 bytes).
     * @param public_key The claimant's public key.
     * @param context Application specific context string used during prove.
     * @return true if valid.
     */
    static bool verify(
        std::span<const uint8_t, PROOF_SIZE> proof,
        std::span<const uint8_t, 32> public_key,
        std::span<const uint8_t> context) noexcept;
};

} // namespace nit::crypto::osnova
