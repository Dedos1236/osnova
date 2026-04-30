#pragma once

#include <cstdint>
#include <span>
#include <vector>

namespace nit::crypto::osnova {

/**
 * @brief NTRU Public-Key Cryptosystem (Lattice-based PQC).
 * OSNOVA implementation of NTRU for Key Encapsulation (KEM) and encryption.
 * Extremely fast and secure against quantum computers.
 */
class Ntru {
public:
    // Typical NTRU-HPS 2048-509 parameters
    static constexpr size_t PUBLIC_KEY_SIZE = 699;
    static constexpr size_t PRIVATE_KEY_SIZE = 935;
    static constexpr size_t CIPHERTEXT_SIZE = 699;
    static constexpr size_t SHARED_SECRET_SIZE = 32;

    /**
     * @brief Generate an NTRU keypair.
     */
    static bool generate_keypair(
        std::vector<uint8_t>& public_key,
        std::vector<uint8_t>& private_key) noexcept;

    /**
     * @brief Encapsulate a shared secret against the public key.
     */
    static bool encapsulate(
        std::vector<uint8_t>& ciphertext_out,
        std::vector<uint8_t>& shared_secret_out,
        std::span<const uint8_t> public_key) noexcept;

    /**
     * @brief Decapsulate the ciphertext to recover the shared secret.
     */
    static bool decapsulate(
        std::vector<uint8_t>& shared_secret_out,
        std::span<const uint8_t> ciphertext,
        std::span<const uint8_t> private_key) noexcept;
};

} // namespace nit::crypto::osnova
