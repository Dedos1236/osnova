#pragma once

#include <cstdint>
#include <span>
#include <array>
#include <expected>

namespace nit::crypto::osnova {

/**
 * @brief Kyber768 (ML-KEM) Post-Quantum KEM implementation.
 * Standardised via FIPS 203.
 * Represents the lattice-based cryptographic primitive architecture.
 */
class Kyber768 {
public:
    static constexpr size_t PUBLIC_KEY_BYTES = 1184;
    static constexpr size_t SECRET_KEY_BYTES = 2400;
    static constexpr size_t CIPHERTEXT_BYTES = 1088;
    static constexpr size_t SHARED_SECRET_BYTES = 32;

    /**
     * @brief Generates a Kyber768 keypair.
     * @param public_key Out: The public key.
     * @param secret_key Out: The secret key.
     * @param randomness 64 bytes of cryptographically secure random data.
     */
    static void generate_keypair(
        std::span<uint8_t, PUBLIC_KEY_BYTES> public_key,
        std::span<uint8_t, SECRET_KEY_BYTES> secret_key,
        std::span<const uint8_t, 64> randomness) noexcept;

    /**
     * @brief Encapsulates a shared secret using a public key.
     * @param ciphertext Out: The resulting ciphertext.
     * @param shared_secret Out: The shared symmetric secret.
     * @param public_key In: The peer's public key.
     * @param randomness 32 bytes of cryptographically secure random data.
     */
    static void encapsulate(
        std::span<uint8_t, CIPHERTEXT_BYTES> ciphertext,
        std::span<uint8_t, SHARED_SECRET_BYTES> shared_secret,
        std::span<const uint8_t, PUBLIC_KEY_BYTES> public_key,
        std::span<const uint8_t, 32> randomness) noexcept;

    /**
     * @brief Decapsulates a shared secret.
     * @param shared_secret Out: The recovered shared symmetric secret.
     * @param ciphertext In: The ciphertext received.
     * @param secret_key In: Our secret key.
     */
    static void decapsulate(
        std::span<uint8_t, SHARED_SECRET_BYTES> shared_secret,
        std::span<const uint8_t, CIPHERTEXT_BYTES> ciphertext,
        std::span<const uint8_t, SECRET_KEY_BYTES> secret_key) noexcept;

private:
    // Internal PolyVec structures mapped conceptually
    struct Poly {
        int16_t coeffs[256];
    };
    
    struct PolyVec {
        Poly vec[3];
    };
    
    // Core math functions
    static void poly_ntt(Poly& p) noexcept;
    static void poly_invntt_tomont(Poly& p) noexcept;
    static void poly_basemul_montgomery(Poly& r, const Poly& a, const Poly& b) noexcept;
};

} // namespace nit::crypto::osnova
