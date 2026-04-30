#pragma once

#include <cstdint>
#include <span>
#include <array>

namespace nit::crypto::osnova {

/**
 * @brief ML-DSA (Dilithium) Post-Quantum Digital Signature Algorithm.
 * Lattice-based signature scheme standard (FIPS 204).
 */
class Dilithium5 {
public:
    static constexpr size_t PUBLIC_KEY_BYTES = 2592;
    static constexpr size_t SECRET_KEY_BYTES = 4864;
    static constexpr size_t SIGNATURE_BYTES  = 4595;

    Dilithium5() noexcept = default;

    /**
     * @brief Generates a Dilithium5 keypair.
     */
    static void generate_keypair(
        std::span<uint8_t, PUBLIC_KEY_BYTES> public_key,
        std::span<uint8_t, SECRET_KEY_BYTES> secret_key,
        std::span<const uint8_t, 32> seed) noexcept;

    /**
     * @brief Signs a message using ML-DSA.
     */
    static void sign(
        std::span<uint8_t, SIGNATURE_BYTES> signature,
        std::span<const uint8_t> message,
        std::span<const uint8_t, SECRET_KEY_BYTES> secret_key) noexcept;

    /**
     * @brief Verifies an ML-DSA signature.
     * @return true if valid.
     */
    static bool verify(
        std::span<const uint8_t, SIGNATURE_BYTES> signature,
        std::span<const uint8_t> message,
        std::span<const uint8_t, PUBLIC_KEY_BYTES> public_key) noexcept;

private:
    struct Poly {
        int32_t coeffs[256];
    };
    
    // In Dilithium5, vectors are length 8 (k) and 6 (l)
    struct PolyVecL {
        Poly vec[6];
    };
    
    struct PolyVecK {
        Poly vec[8];
    };

    static void expand_A(PolyVecK matrix_A[6], const uint8_t rho[32]) noexcept;
    static void expand_S(PolyVecL& s1, PolyVecK& s2, const uint8_t rho_prime[64]) noexcept;
    static void poly_ntt(Poly& p) noexcept;
};

} // namespace nit::crypto::osnova
