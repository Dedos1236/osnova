#pragma once

#include <cstdint>
#include <vector>
#include <span>

namespace nit::crypto::osnova {

/**
 * @brief GOST R 34.12-2015 (Kuznyechik) Block Cipher.
 * Certified symmetric block cipher compliant with Russian Federation standard.
 * 128-bit block size, 256-bit key size.
 * Highly robust against linear and differential cryptanalysis.
 */
class GostKuznyechik {
public:
    static constexpr size_t BLOCK_SIZE = 16; // 128 bits
    static constexpr size_t KEY_SIZE = 32;   // 256 bits

    explicit GostKuznyechik(std::span<const uint8_t, KEY_SIZE> key);
    ~GostKuznyechik();

    /**
     * @brief Encrypt a single 128-bit block.
     * @param out Output buffer of 16 bytes.
     * @param in Input buffer of 16 bytes.
     */
    void encrypt_block(std::span<uint8_t, BLOCK_SIZE> out, std::span<const uint8_t, BLOCK_SIZE> in) const;

    /**
     * @brief Decrypt a single 128-bit block.
     * @param out Output buffer of 16 bytes.
     * @param in Input buffer of 16 bytes.
     */
    void decrypt_block(std::span<uint8_t, BLOCK_SIZE> out, std::span<const uint8_t, BLOCK_SIZE> in) const;

private:
    std::vector<std::vector<uint8_t>> round_keys_; // 10 round keys

    void key_schedule(std::span<const uint8_t, KEY_SIZE> key);
    
    // Sub-layer transformations
    void non_linear_layer(std::vector<uint8_t>& state) const; // S
    void linear_layer(std::vector<uint8_t>& state) const;     // L
    void xor_key(std::vector<uint8_t>& state, const std::vector<uint8_t>& rk) const; // X
};

} // namespace nit::crypto::osnova
