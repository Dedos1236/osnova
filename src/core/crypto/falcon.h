#pragma once

#include <cstdint>
#include <span>
#include <vector>

namespace nit::crypto::osnova {

/**
 * @brief Falcon (Fast-Fourier Lattice-based Compact Signatures over NTRU).
 * NIST Post-Quantum Cryptography standard for digital signatures.
 * OSNOVA uses Falcon for compact post-quantum signatures when BLS is not required.
 */
class Falcon {
public:
    static constexpr size_t PRIVATE_KEY_SIZE_512 = 1281;
    static constexpr size_t PUBLIC_KEY_SIZE_512 = 897;
    static constexpr size_t SIGNATURE_SIZE_512 = 666;

    static constexpr size_t PRIVATE_KEY_SIZE_1024 = 2305;
    static constexpr size_t PUBLIC_KEY_SIZE_1024 = 1793;
    static constexpr size_t SIGNATURE_SIZE_1024 = 1280;

    enum class Degree {
        N_512 = 512,
        N_1024 = 1024
    };

    /**
     * @brief Generate a Falcon keypair.
     */
    static bool generate_keypair(
        Degree degree,
        std::vector<uint8_t>& public_key,
        std::vector<uint8_t>& private_key) noexcept;

    /**
     * @brief Sign a message using Falcon.
     */
    static bool sign(
        Degree degree,
        std::vector<uint8_t>& signature,
        std::span<const uint8_t> private_key,
        std::span<const uint8_t> message) noexcept;

    /**
     * @brief Verify a Falcon signature.
     */
    static bool verify(
        Degree degree,
        std::span<const uint8_t> signature,
        std::span<const uint8_t> public_key,
        std::span<const uint8_t> message) noexcept;
};

} // namespace nit::crypto::osnova
