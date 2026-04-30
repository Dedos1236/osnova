#pragma once

#include <cstdint>
#include <span>
#include <vector>

namespace nit::crypto::osnova {

/**
 * @brief SPHINCS+ Post-Quantum stateless hash-based signature scheme.
 * Highly conservative security guarantees as it strictly relies on collision-resistant hashes.
 */
class SphincsPlus {
public:
    static constexpr size_t PUBLIC_KEY_SIZE = 32;
    static constexpr size_t PRIVATE_KEY_SIZE = 64;
    static constexpr size_t SIGNATURE_SIZE = 7856; // example parameter set (SPHINCS+-SHA2-128s)

    enum class ParameterSet {
        SHA2_128F,
        SHA2_128S,
        SHAKE_128F,
        SHAKE_128S
    };

    /**
     * @brief Generate a SPHINCS+ key pair.
     */
    static bool generate_keypair(
        ParameterSet params,
        std::vector<uint8_t>& public_key,
        std::vector<uint8_t>& private_key) noexcept;

    /**
     * @brief Sign a message using SPHINCS+. 
     */
    static bool sign(
        ParameterSet params,
        std::vector<uint8_t>& signature,
        std::span<const uint8_t> private_key,
        std::span<const uint8_t> message) noexcept;

    /**
     * @brief Verify a SPHINCS+ signature.
     */
    static bool verify(
        ParameterSet params,
        std::span<const uint8_t> signature,
        std::span<const uint8_t> public_key,
        std::span<const uint8_t> message) noexcept;
};

} // namespace nit::crypto::osnova
