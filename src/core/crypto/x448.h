#pragma once

#include <cstdint>
#include <span>

namespace nit::crypto::osnova {

/**
 * @brief X448 Elliptic Curve Diffie-Hellman (RFC 7748).
 * Provides higher security margin (~224-bit security) than Curve25519.
 * Utilized for Top Secret enclave communication streams.
 */
class X448 {
public:
    static constexpr size_t KEY_SIZE = 56;

    X448() noexcept = default;

    /**
     * @brief Evaluates the X448 scalar multiplication.
     * @param shared_secret The output 56-byte derived coordinate.
     * @param secret_key The 56-byte scalar.
     * @param public_key The 56-byte u-coordinate of the peer.
     */
    static void shared_secret(
        std::span<uint8_t, KEY_SIZE> shared_secret,
        std::span<const uint8_t, KEY_SIZE> secret_key,
        std::span<const uint8_t, KEY_SIZE> public_key) noexcept;

    /**
     * @brief Generates public key from secret key.
     * Computes scalar multiplication of the base point.
     */
    static void generate_public_key(
        std::span<uint8_t, KEY_SIZE> public_key,
        std::span<const uint8_t, KEY_SIZE> secret_key) noexcept;

private:
    struct FieldElement {
        uint64_t limbs[8]; // 512 bits to hold 448
    };

    static void decode_scalar(uint8_t k[KEY_SIZE], const uint8_t k_in[KEY_SIZE]) noexcept;
    static void fe_mul(FieldElement& r, const FieldElement& a, const FieldElement& b) noexcept;
    static void fe_sqr(FieldElement& r, const FieldElement& a) noexcept;
    static void fe_add(FieldElement& r, const FieldElement& a, const FieldElement& b) noexcept;
    static void fe_sub(FieldElement& r, const FieldElement& a, const FieldElement& b) noexcept;
    static void fe_invert(FieldElement& r, const FieldElement& a) noexcept;
};

} // namespace nit::crypto::osnova
