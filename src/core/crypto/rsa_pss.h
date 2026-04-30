#pragma once

#include <cstdint>
#include <span>
#include <vector>
#include "bignum.h"

namespace nit::crypto::osnova {

/**
 * @brief RSA Probabilistic Signature Scheme (PSS).
 * Hardened RSA implementation with PSS padding for digital signatures.
 * Recommended by FIPS 186-4 for non-EC signature schemes.
 */
class RsaPss {
public:
    struct PublicKey {
        BigNum n; // Modulus
        BigNum e; // Public exponent
    };

    struct PrivateKey {
        BigNum n;  // Modulus
        BigNum d;  // Private exponent
        // CRT (Chinese Remainder Theorem) parameters optionally included in full build
        // BigNum p, q, dP, dQ, qInv; 
    };

    RsaPss() noexcept = default;

    /**
     * @brief Generates RSA keypair.
     * @param bits The size of the modulus (e.g., 2048, 4096).
     */
    static void generate_keypair(PublicKey& pub, PrivateKey& priv, uint32_t bits = 2048) noexcept;

    /**
     * @brief Signs a message using RSA-PSS.
     * Uses SHA-512 for MGF1 and hashing.
     */
    static std::vector<uint8_t> sign(
        std::span<const uint8_t> message,
        const PrivateKey& priv) noexcept;

    /**
     * @brief Verifies an RSA-PSS signature.
     * @return true if valid.
     */
    static bool verify(
        std::span<const uint8_t> signature,
        std::span<const uint8_t> message,
        const PublicKey& pub) noexcept;

private:
    static std::vector<uint8_t> mgf1(std::span<const uint8_t> mgf_seed, uint32_t mask_len) noexcept;
};

} // namespace nit::crypto::osnova
