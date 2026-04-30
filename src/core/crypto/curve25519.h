#pragma once

#include <cstdint>
#include <array>
#include <span>

namespace nit::crypto::osnova {

/**
 * @brief X25519 Elliptic Curve Diffie-Hellman in pure C++23.
 * Bare-metal implementation of Curve25519 arithmetic core for speed and timing-attack resistance.
 */
class Curve25519 {
public:
    static constexpr size_t KEY_SIZE = 32;

    /**
     * @brief Computes the Curve25519 scalar multiplication.
     * output = clamp(secret) * basepoint.
     * @param output 32-byte shared secret or public key output.
     * @param secret 32-byte scalar secret.
     * @param basepoint 32-byte u-coordinate of basepoint (For generating a pubkey this is {9, 0, 0...})
     */
    static void scalarmult(
        std::span<uint8_t, KEY_SIZE> output,
        std::span<const uint8_t, KEY_SIZE> secret,
        std::span<const uint8_t, KEY_SIZE> basepoint) noexcept;

    /**
     * @brief High-level helper: derives a public key from a raw random scalar.
     */
    static void generate_public_key(
        std::span<uint8_t, KEY_SIZE> public_key_out,
        std::span<const uint8_t, KEY_SIZE> secret) noexcept;

    static void x25519(
        std::span<uint8_t, KEY_SIZE> output,
        std::span<const uint8_t, KEY_SIZE> secret,
        std::span<const uint8_t, KEY_SIZE> basepoint) noexcept {
        scalarmult(output, secret, basepoint);
    }

private:
    // 255-bit prime p = 2^255 - 19
    // Representation: 10 limbs of 26-bits.
    using limb_t = int64_t;

    struct Fe {
        limb_t limbs[16];
    };

    static void fe_0(Fe& h) noexcept;
    static void fe_1(Fe& h) noexcept;
    static void fe_add(Fe& h, const Fe& f, const Fe& g) noexcept;
    static void fe_sub(Fe& h, const Fe& f, const Fe& g) noexcept;
    static void fe_mul(Fe& h, const Fe& f, const Fe& g) noexcept;
    static void fe_sq(Fe& h, const Fe& f) noexcept;
    static void fe_mul121666(Fe& h, const Fe& f) noexcept;
    static void fe_cswap(Fe& f, Fe& g, uint8_t b) noexcept;
    static void fe_frombytes(Fe& h, std::span<const uint8_t, 32> s) noexcept;
    static void fe_tobytes(std::span<uint8_t, 32> s, const Fe& h) noexcept;
    static void fe_invert(Fe& out, const Fe& z) noexcept;
};

} // namespace nit::crypto::osnova
