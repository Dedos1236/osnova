#pragma once

#include <cstdint>
#include <array>
#include <span>
#include <vector>
#include <expected>
#include <string_view>
#include <memory>

namespace nit::crypto::osnova {

// ============================================================================
// OSNOVA Protocol: Constants & Types
// Hybrid Post-Quantum Cryptography (X25519 + Kyber-768)
// AEAD: ChaCha20-Poly1305 or AES-256-GCM
// Signatures: Ed25519 + Dilithium3
// ============================================================================

constexpr size_t OSNOVA_SYMMETRIC_KEY_SIZE = 32;
constexpr size_t OSNOVA_MAC_SIZE = 16;
constexpr size_t OSNOVA_NONCE_SIZE = 12;

// Kyber768 constants
constexpr size_t KYBER_PUBLIC_KEY_BYTES = 1184;
constexpr size_t KYBER_SECRET_KEY_BYTES = 2400;
constexpr size_t KYBER_CIPHERTEXT_BYTES = 1088;
constexpr size_t KYBER_SS_BYTES = 32;

// X25519 constants
constexpr size_t X25519_KEY_BYTES = 32;

using SymmetricKey = std::array<std::byte, OSNOVA_SYMMETRIC_KEY_SIZE>;
using Nonce = std::array<std::byte, OSNOVA_NONCE_SIZE>;
using Mac = std::array<std::byte, OSNOVA_MAC_SIZE>;

struct HybridPublicKey {
    std::array<std::byte, X25519_KEY_BYTES> x25519_pk;
    std::array<std::byte, KYBER_PUBLIC_KEY_BYTES> kyber_pk;
};

struct HybridSecretKey {
    std::array<std::byte, X25519_KEY_BYTES> x25519_sk;
    std::array<std::byte, KYBER_SECRET_KEY_BYTES> kyber_sk;
};

struct HybridCiphertext {
    std::array<std::byte, X25519_KEY_BYTES> x25519_ephemeral_pk;
    std::array<std::byte, KYBER_CIPHERTEXT_BYTES> kyber_ct;
};

enum class CryptoError {
    InvalidKeySize,
    DecryptionFailed,
    AuthenticationFailed,
    BufferTooSmall,
    EntropyDepleted,
    HardwareFault
};

/**
 * @brief OSNOVA Core Engine. 
 * Provides bare-metal C++ APIs for hybrid post-quantum cryptography.
 * Designed to execute entirely within the TrustZone / Secure Enclave where possible.
 */
class OsnovaEngine {
public:
    OsnovaEngine();
    ~OsnovaEngine();

    OsnovaEngine(const OsnovaEngine&) = delete;
    OsnovaEngine& operator=(const OsnovaEngine&) = delete;

    // ------------------------------------------------------------------------
    // KEM (Key Encapsulation Mechanism)
    // ------------------------------------------------------------------------
    
    /**
     * @brief Generates a hybrid X25519 + Kyber768 keypair.
     * Pulls true randomness from hardware RNG (/dev/urandom or RDRAND).
     */
    [[nodiscard]] std::expected<void, CryptoError> generate_keypair(HybridPublicKey& pub, HybridSecretKey& sec) noexcept;

    /**
     * @brief Encapsulates a shared secret for the target public key.
     * @return Hybrid ciphertext to send to the peer, and the derived 32-byte shared secret.
     */
    [[nodiscard]] std::expected<std::pair<HybridCiphertext, SymmetricKey>, CryptoError> encapsulate(
        const HybridPublicKey& peer_pub) noexcept;

    /**
     * @brief Decapsulates the shared secret using our secret key.
     */
    [[nodiscard]] std::expected<SymmetricKey, CryptoError> decapsulate(
        const HybridCiphertext& ct, const HybridSecretKey& my_sec) noexcept;

    // ------------------------------------------------------------------------
    // AEAD (Authenticated Encryption with Associated Data)
    // ------------------------------------------------------------------------

    /**
     * @brief Encrypts plaintext in-place using ChaCha20-Poly1305.
     * Zero-allocation, memory-safe span bindings.
     * @param buffer Pre-allocated buffer containing plaintext, with at least 16 bytes extra capacity for the MAC.
     * @param pt_len Length of the actual plaintext inside the buffer.
     * @return New length of the payload (pt_len + 16).
     */
    [[nodiscard]] std::expected<size_t, CryptoError> encrypt_in_place(
        std::span<std::byte> buffer, 
        size_t pt_len, 
        const SymmetricKey& key, 
        const Nonce& nonce, 
        std::span<const std::byte> aad = {}) noexcept;

    /**
     * @brief Decrypts ciphertext in-place and verifies MAC.
     * @return Length of the plaintext on success.
     */
    [[nodiscard]] std::expected<size_t, CryptoError> decrypt_in_place(
        std::span<std::byte> buffer, 
        size_t ct_len, 
        const SymmetricKey& key, 
        const Nonce& nonce, 
        std::span<const std::byte> aad = {}) noexcept;

private:
    struct Impl;
    std::unique_ptr<Impl> pimpl_;
};

} // namespace nit::crypto::osnova
