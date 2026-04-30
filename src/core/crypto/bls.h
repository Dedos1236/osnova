#pragma once

#include <cstdint>
#include <span>
#include <vector>

namespace nit::crypto::osnova {

/**
 * @brief Boneh-Lynn-Shacham (BLS) Signatures over pairing-friendly curves (e.g., BLS12-381).
 * Excellent for OSNOVA mesh network because they allow signature aggregation: 
 * multiple signatures from different nodes can be compressed into a single signature.
 */
class BlsSignatures {
public:
    static constexpr size_t PRIVATE_KEY_SIZE = 32;
    static constexpr size_t PUBLIC_KEY_SIZE = 48; // G1 compressed
    static constexpr size_t SIGNATURE_SIZE = 96;  // G2 compressed

    /**
     * @brief Generate a BLS keypair.
     */
    static void generate_keypair(
        std::span<uint8_t, PUBLIC_KEY_SIZE> public_key,
        std::span<uint8_t, PRIVATE_KEY_SIZE> private_key) noexcept;

    /**
     * @brief Sign a message using a BLS private key.
     */
    static void sign(
        std::span<uint8_t, SIGNATURE_SIZE> signature,
        std::span<const uint8_t, PRIVATE_KEY_SIZE> private_key,
        std::span<const uint8_t> message) noexcept;

    /**
     * @brief Verify a BLS signature.
     */
    static bool verify(
        std::span<const uint8_t, SIGNATURE_SIZE> signature,
        std::span<const uint8_t, PUBLIC_KEY_SIZE> public_key,
        std::span<const uint8_t> message) noexcept;

    /**
     * @brief Aggregate multiple signatures into one.
     * @param out_signature The resulting aggregated signature (96 bytes).
     * @param signatures A list of signatures to aggregate.
     * @return true on success.
     */
    static bool aggregate_signatures(
        std::span<uint8_t, SIGNATURE_SIZE> out_signature,
        const std::vector<std::vector<uint8_t>>& signatures) noexcept;

    /**
     * @brief Verify an aggregated signature against multiple public keys and messages.
     * @param signature The aggregated signature.
     * @param public_keys List of public keys.
     * @param messages List of messages (must correspond 1:1 with public keys).
     * @return true if valid.
     */
    static bool verify_aggregated(
        std::span<const uint8_t, SIGNATURE_SIZE> signature,
        const std::vector<std::vector<uint8_t>>& public_keys,
        const std::vector<std::vector<uint8_t>>& messages) noexcept;
};

} // namespace nit::crypto::osnova
