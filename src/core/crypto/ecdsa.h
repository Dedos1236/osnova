#pragma once

#include <cstdint>
#include <span>
#include <vector>
#include "bignum.h"

namespace nit::crypto::osnova {

/**
 * @brief Elliptic Curve Digital Signature Algorithm (ECDSA).
 * Hardened NIST P-256 (secp256r1) curve implementation.
 */
class EcdsaP256 {
public:
    static constexpr size_t PRIVATE_KEY_BYTES = 32;
    static constexpr size_t PUBLIC_KEY_BYTES = 65; // Uncompressed (0x04 || X || Y)
    static constexpr size_t SIGNATURE_BYTES = 64;  // (R || S)

    struct Point {
        BigNum x;
        BigNum y;
        bool is_infinity;
    };

    EcdsaP256() noexcept = default;

    /**
     * @brief Generates ECDSA keypair.
     */
    static void generate_keypair(
        std::span<uint8_t, PUBLIC_KEY_BYTES> public_key,
        std::span<uint8_t, PRIVATE_KEY_BYTES> private_key) noexcept;

    /**
     * @brief Signs a message using ECDSA.
     */
    static std::vector<uint8_t> sign(
        std::span<const uint8_t> message,
        std::span<const uint8_t, PRIVATE_KEY_BYTES> private_key) noexcept;

    /**
     * @brief Verifies an ECDSA signature.
     */
    static bool verify(
        std::span<const uint8_t> signature,
        std::span<const uint8_t> message,
        std::span<const uint8_t, PUBLIC_KEY_BYTES> public_key) noexcept;

private:
    static const BigNum p; // Prime field
    static const BigNum a; // Curve parameter a
    static const BigNum b; // Curve parameter b
    static const BigNum n; // Curve order
    static const Point G;  // Generator point

    // Point arithmetic
    static Point point_add(const Point& p1, const Point& p2) noexcept;
    static Point point_double(const Point& p1) noexcept;
    static Point scalar_mult(const Point& p1, const BigNum& k) noexcept;
};

} // namespace nit::crypto::osnova
