#pragma once

#include <cstdint>
#include <span>
#include <vector>

namespace nit::crypto::osnova {

/**
 * @brief Post-Quantum Extended Triple Diffie-Hellman (PQ-X3DH).
 * Combines standard X3DH (Curve25519) with a Post-Quantum KEM (Kyber768).
 */
class PqX3dh {
public:
    static constexpr size_t SHARED_SECRET_SIZE = 32;

    struct Config {
        std::span<const uint8_t, 32> info; // Application info string
    };

    /**
     * @brief Perform PQ-X3DH as the initiator (Alice).
     * 
     * @param sk Output shared secret (32 bytes).
     * @param ct Output Kyber ciphertext (1088 bytes for Kyber768).
     * @param IK_A Alice's Identity Key pair (private).
     * @param EK_A Alice's Ephemeral Key pair (private).
     * @param IK_B Bob's Identity Key (public).
     * @param SPK_B Bob's Signed Prekey (public).
     * @param OPK_B Bob's One-Time Prekey (public, optional).
     * @param PQ_SPK_B Bob's Post-Quantum Signed Prekey (Kyber public key, 1184 bytes).
     * @param config Application config for HKDF.
     * @return true on success.
     */
    static bool initiate(
        std::span<uint8_t, 32> sk,
        std::span<uint8_t, 1088> ct,
        std::span<const uint8_t, 32> IK_A_priv,
        std::span<const uint8_t, 32> EK_A_priv,
        std::span<const uint8_t, 32> IK_B_pub,
        std::span<const uint8_t, 32> SPK_B_pub,
        std::span<const uint8_t> OPK_B_pub, // Curve25519 Optional
        std::span<const uint8_t, 1184> PQ_SPK_B_pub,
        const Config& config) noexcept;

    /**
     * @brief Perform PQ-X3DH as the responder (Bob).
     * 
     * @param sk Output shared secret (32 bytes).
     * @param IK_B Bob's Identity Key pair (private).
     * @param SPK_B Bob's Signed Prekey pair (private).
     * @param OPK_B Bob's One-Time Prekey pair (private, optional).
     * @param PQ_SPK_B Bob's Post-Quantum Signed Prekey (Kyber secret key, 2400 bytes).
     * @param ct The Kyber ciphertext received from Alice.
     * @param IK_A Alice's Identity Key (public).
     * @param EK_A Alice's Ephemeral Key (public).
     * @param config Application config for HKDF.
     * @return true on success.
     */
    static bool respond(
        std::span<uint8_t, 32> sk,
        std::span<const uint8_t, 32> IK_B_priv,
        std::span<const uint8_t, 32> SPK_B_priv,
        std::span<const uint8_t> OPK_B_priv, // Curve25519 Optional
        std::span<const uint8_t, 2400> PQ_SPK_B_priv,
        std::span<const uint8_t, 1088> ct,
        std::span<const uint8_t, 32> IK_A_pub,
        std::span<const uint8_t, 32> EK_A_pub,
        const Config& config) noexcept;
};

} // namespace nit::crypto::osnova
