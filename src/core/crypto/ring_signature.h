#pragma once

#include <cstdint>
#include <vector>
#include <span>

namespace nit::crypto::osnova {

/**
 * @brief Ring Signatures (Linkable Spontaneous Anonymous Group).
 * Core cryptographic primitive for sender anonymity in OSNOVA protocol.
 * Enables signing a message on behalf of a group, without revealing which member signed it.
 */
class RingSignature {
public:
    static constexpr size_t PUBLIC_KEY_SIZE = 32;  // Curve25519 or Ed25519 compression
    static constexpr size_t PRIVATE_KEY_SIZE = 32;
    static constexpr size_t KEY_IMAGE_SIZE = 32;   // Used to prevent double-spending/sybil

    struct Signature {
        std::vector<uint8_t> key_image;
        std::vector<uint8_t> c_0;
        std::vector<std::vector<uint8_t>> r;
    };

    /**
     * @brief Generate a linkable ring signature.
     * @param message The message to sign.
     * @param public_keys The ring of public keys (decoys + real).
     * @param real_secret_key The signer's private key.
     * @param real_index The index of the real signer's public key in the ring.
     */
    static Signature sign(
        std::span<const uint8_t> message,
        const std::vector<std::vector<uint8_t>>& public_keys,
        std::span<const uint8_t, PRIVATE_KEY_SIZE> real_secret_key,
        size_t real_index) noexcept;

    /**
     * @brief Verify a linkable ring signature.
     */
    static bool verify(
        std::span<const uint8_t> message,
        const std::vector<std::vector<uint8_t>>& public_keys,
        const Signature& sig) noexcept;

    /**
     * @brief Extract the key image (linkability tag) from the signature.
     * If two signatures have the same key image, they were created by the same 
     * private key, enabling strict duplicate detection while maintaining anonymity.
     */
    static std::vector<uint8_t> extract_key_image(const Signature& sig) noexcept;

    /**
     * @brief Combine (serialize) a signature to bytes.
     */
    static std::vector<uint8_t> serialize(const Signature& sig) noexcept;

    /**
     * @brief Deserialize a signature from bytes.
     */
    static bool deserialize(Signature& sig, std::span<const uint8_t> data, size_t ring_size) noexcept;
};

} // namespace nit::crypto::osnova
