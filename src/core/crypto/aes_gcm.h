#pragma once

#include <cstdint>
#include <span>
#include <array>

namespace nit::crypto::osnova {

/**
 * @brief AES-256 GCM (Galois/Counter Mode).
 * Authenticated Encryption with Associated Data (AEAD).
 * Robust standard block cipher used when hardware acceleration (AES-NI) is available,
 * serving as an alternative/fallback to ChaCha20-Poly1305.
 */
class Aes256Gcm {
public:
    static constexpr size_t KEY_SIZE = 32;
    static constexpr size_t NONCE_SIZE = 12;
    static constexpr size_t TAG_SIZE = 16;
    static constexpr size_t BLOCK_SIZE = 16;

    Aes256Gcm() noexcept = default;

    /**
     * @brief Encrypt and Authenticate (AEAD).
     * @param ciphertext Output encrypted buffer (must be same size as plaintext).
     * @param tag Output MAC tag (16 bytes).
     * @param plaintext Input data to encrypt.
     * @param ad Additional Authenticated Data (AAD) not encrypted but authenticated.
     * @param key 256-bit symmetric key.
     * @param nonce 96-bit nonce.
     */
    static void encrypt(
        std::span<uint8_t> ciphertext,
        std::span<uint8_t, TAG_SIZE> tag,
        std::span<const uint8_t> plaintext,
        std::span<const uint8_t> ad,
        std::span<const uint8_t, KEY_SIZE> key,
        std::span<const uint8_t, NONCE_SIZE> nonce) noexcept;

    /**
     * @brief Decrypt and Verify (AEAD).
     * @return true if authentication succeeds.
     */
    static bool decrypt(
        std::span<uint8_t> plaintext,
        std::span<const uint8_t> ciphertext,
        std::span<const uint8_t, TAG_SIZE> tag,
        std::span<const uint8_t> ad,
        std::span<const uint8_t, KEY_SIZE> key,
        std::span<const uint8_t, NONCE_SIZE> nonce) noexcept;

private:
    // Core AES-256 block function
    static void aes256_encrypt_block(const uint8_t* in, uint8_t* out, const uint32_t* round_keys) noexcept;

    // Key Expansion
    static void aes256_key_expansion(const uint8_t* key, uint32_t* round_keys) noexcept;

    // GF(128) Multiplication for GCM Authentication
    static void gf128_mul(uint64_t x[2], const uint64_t y[2]) noexcept;
    
    // GHASH helper
    static void ghash(uint64_t hash[2], const uint8_t* data, size_t len, const uint64_t h_key[2]) noexcept;
};

} // namespace nit::crypto::osnova
