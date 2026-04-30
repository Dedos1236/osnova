#pragma once

#include <cstdint>
#include <span>

namespace nit::crypto::osnova {

/**
 * @brief XChaCha20 stream cipher.
 * Uses 256-bit key and 192-bit (24 bytes) nonce.
 */
class XChaCha20 {
public:
    static constexpr size_t KEY_SIZE = 32;
    static constexpr size_t NONCE_SIZE = 24;
    static constexpr size_t BLOCK_SIZE = 64;

    /**
     * @brief Encrypt or decrypt data using XChaCha20.
     * 
     * @param out Output buffer (ciphertext or plaintext)
     * @param in Input buffer (plaintext or ciphertext)
     * @param key 32-byte key
     * @param nonce 24-byte nonce
     * @param counter Initial block counter
     */
    static void process(
        std::span<uint8_t> out,
        std::span<const uint8_t> in,
        std::span<const uint8_t, KEY_SIZE> key,
        std::span<const uint8_t, NONCE_SIZE> nonce,
        uint32_t counter = 0) noexcept;

    /**
     * @brief HChaCha20 core function for subkey derivation.
     * 
     * @param out 32-byte output derived key
     * @param key 32-byte input key
     * @param nonce 16-byte input nonce (only first 16 bytes of XChaCha20 nonce)
     */
    static void hchacha20(
        std::span<uint8_t, KEY_SIZE> out,
        std::span<const uint8_t, KEY_SIZE> key,
        std::span<const uint8_t, 16> nonce) noexcept;
};

} // namespace nit::crypto::osnova
