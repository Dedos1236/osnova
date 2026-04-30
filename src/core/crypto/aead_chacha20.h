#pragma once

#include "chacha20.h"
#include "poly1305.h"
#include <vector>
#include <expected>

namespace nit::crypto::osnova {

/**
 * @brief Zero-allocation AEAD ChaCha20-Poly1305 Cipher.
 * RFC 8439 compliant hardware-capable C++ driver.
 */
class ChaCha20Poly1305 {
public:
    static constexpr size_t KEY_SIZE = 32;
    static constexpr size_t NONCE_SIZE = 12;
    static constexpr size_t MAC_SIZE = 16;

    /**
     * @brief Encrypts plaintext and generates MAC in O(1) memory space.
     * @param key 256-bit symmetric key.
     * @param nonce 96-bit nonce.
     * @param aad Associated Data to authenticate but not encrypt.
     * @param plaintext Input data.
     * @param ciphertext Output buffer (must be size of plaintext).
     * @param mac Output 16-byte MAC.
     */
    static void encrypt(
        std::span<const uint8_t, KEY_SIZE> key,
        std::span<const uint8_t, NONCE_SIZE> nonce,
        std::span<const uint8_t> aad,
        std::span<const uint8_t> plaintext,
        std::span<uint8_t> ciphertext,
        std::span<uint8_t, MAC_SIZE> mac) noexcept;

    /**
     * @brief Authenticates and decrypts ciphertext.
     * @return true if MAC is valid and decryption succeeds, false otherwise (Constant Time evaluation).
     */
    static bool decrypt(
        std::span<const uint8_t, KEY_SIZE> key,
        std::span<const uint8_t, NONCE_SIZE> nonce,
        std::span<const uint8_t> aad,
        std::span<const uint8_t> ciphertext,
        std::span<const uint8_t, MAC_SIZE> in_mac,
        std::span<uint8_t> plaintext) noexcept;
        
private:
    static void pad16_update(Poly1305& poly, size_t length) noexcept;
    static void length_update(Poly1305& poly, size_t aad_len, size_t ct_len) noexcept;
    static bool constant_time_eq(std::span<const uint8_t, MAC_SIZE> a, std::span<const uint8_t, MAC_SIZE> b) noexcept;
};

} // namespace nit::crypto::osnova
