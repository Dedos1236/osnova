#pragma once

#include <vector>
#include <cstdint>
#include <span>

namespace nit::crypto::osnova {

/**
 * @brief Elliptic Curve Integrated Encryption Scheme (ECIES).
 * A hybrid encryption setup: uses asymmetric keys to securely share a symmetric key,
 * which then encrypts the bulk payload.
 * 
 * OSNOVA uses an advanced ECIES configuration: X25519 for Key Exchange, 
 * HKDF-SHA256 for Key Derivation, and AES-256-GCM for symmetric payload.
 */
class Ecies {
public:
    /**
     * @brief Encrypt a message to a recipient's public key.
     * @param ciphertext Output vector (will contain: Ephemeral Public Key || GCM IV || GCM Ciphertext || GCM Tag).
     * @param recipient_public_key X25519 public key of the recipient (32 bytes).
     * @param plaintext Data to encrypt.
     * @return true on success.
     */
    static bool encrypt(
        std::vector<uint8_t>& ciphertext,
        std::span<const uint8_t, 32> recipient_public_key,
        std::span<const uint8_t> plaintext);

    /**
     * @brief Decrypt a message using our private key.
     * @param plaintext Decrypted output.
     * @param recipient_private_key Our X25519 private key (32 bytes).
     * @param ciphertext Encrypted payload from `encrypt()`.
     * @return true if decryption and MAC verification succeed.
     */
    static bool decrypt(
        std::vector<uint8_t>& plaintext,
        std::span<const uint8_t, 32> recipient_private_key,
        std::span<const uint8_t> ciphertext);
};

} // namespace nit::crypto::osnova
