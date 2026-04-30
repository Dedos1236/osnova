#pragma once

#include <cstdint>
#include <span>

namespace nit::crypto::osnova {

/**
 * @brief SM4 Block Cipher.
 * Chinese Commercial Cryptography Standard (GB/T 32907-2016).
 * Standard encryption for OSNOVA payload wrapping in compliant networks.
 */
class Sm4 {
public:
    static constexpr size_t KEY_SIZE = 16;
    static constexpr size_t BLOCK_SIZE = 16;

    Sm4() = default;

    /**
     * @brief Set the encryption key.
     */
    void set_encrypt_key(std::span<const uint8_t, KEY_SIZE> key) noexcept;

    /**
     * @brief Set the decryption key.
     */
    void set_decrypt_key(std::span<const uint8_t, KEY_SIZE> key) noexcept;

    /**
     * @brief Encrypt a 16-byte block in place.
     */
    void encrypt_block(std::span<uint8_t, BLOCK_SIZE> block) const noexcept;

    /**
     * @brief Decrypt a 16-byte block in place.
     */
    void decrypt_block(std::span<uint8_t, BLOCK_SIZE> block) const noexcept;

private:
    uint32_t rk_[32]; // Round keys

    void set_key(std::span<const uint8_t, KEY_SIZE> key, bool encrypt) noexcept;
};

} // namespace nit::crypto::osnova
