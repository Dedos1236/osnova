#pragma once

#include <cstdint>
#include <span>
#include <array>
#include <vector>

namespace nit::crypto::osnova {

/**
 * @brief Ed25519 Digital Signature Algorithm.
 * RFC 8032 compliant bare-metal C++ implementation.
 * Used for identity verification and handshake authentication.
 */
class Ed25519 {
public:
    static constexpr size_t PUBLIC_KEY_SIZE = 32;
    static constexpr size_t SECRET_KEY_SIZE = 64; // Base secret (32) + derived pk (32)
    static constexpr size_t SIGNATURE_SIZE = 64;

    /**
     * @brief Derives the public key and full secret key from a 32-byte seed.
     */
    static void generate_keypair(
        std::span<uint8_t, PUBLIC_KEY_SIZE> public_key,
        std::span<uint8_t, SECRET_KEY_SIZE> secret_key,
        std::span<const uint8_t, 32> seed) noexcept;

    /**
     * @brief Signs a message.
     */
    static void sign(
        std::span<uint8_t, SIGNATURE_SIZE> signature,
        std::span<const uint8_t> message,
        std::span<const uint8_t, PUBLIC_KEY_SIZE> public_key,
        std::span<const uint8_t, SECRET_KEY_SIZE> secret_key) noexcept;

    /**
     * @brief Verifies a signature.
     * @return true if signature is valid.
     */
    static bool verify(
        std::span<const uint8_t, SIGNATURE_SIZE> signature,
        std::span<const uint8_t> message,
        std::span<const uint8_t, PUBLIC_KEY_SIZE> public_key) noexcept;
};

} // namespace nit::crypto::osnova
