#pragma once

#include <cstdint>
#include <span>
#include <vector>

namespace nit::crypto::osnova {

/**
 * @brief AES Key Wrap Algorithm (RFC 3394).
 * Used to securely wrap keys with a master key encryption key (KEK).
 */
class AesKeyWrap {
public:
    /**
     * @brief Wrap a key.
     * 
     * @param out Output wrapped key, must be key.size() + 8 bytes
     * @param kek Key encryption key (16, 24, or 32 bytes for AES-128/192/256)
     * @param key Key to be wrapped (multiple of 8 bytes)
     * @return true if successful
     */
    static bool wrap(
        std::span<uint8_t> out,
        std::span<const uint8_t> kek,
        std::span<const uint8_t> key) noexcept;

    /**
     * @brief Unwrap a key.
     * 
     * @param out Output unwrapped key, must be wrapped_key.size() - 8 bytes
     * @param kek Key encryption key (16, 24, or 32 bytes)
     * @param wrapped_key Wrapped key to unlock
     * @return true if successful and integrity is verified
     */
    static bool unwrap(
        std::span<uint8_t> out,
        std::span<const uint8_t> kek,
        std::span<const uint8_t> wrapped_key) noexcept;
};

} // namespace nit::crypto::osnova
