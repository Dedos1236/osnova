#pragma once

#include <cstdint>
#include <span>
#include <array>

namespace nit::crypto::osnova {

/**
 * @brief HMAC based on SHA-512 (RFC 2104).
 */
class HmacSha512 {
public:
    static constexpr size_t DIGEST_SIZE = 64;
    
    /**
     * @brief Computes HMAC-SHA512.
     * @param key Symmetric key.
     * @param data Input data to authenticate.
     * @param mac Output 64-byte MAC.
     */
    static void compute(
        std::span<const uint8_t> key,
        std::span<const uint8_t> data,
        std::span<uint8_t, DIGEST_SIZE> mac) noexcept;
};

/**
 * @brief HKDF based on HMAC-SHA512 (RFC 5869).
 * Used for secure key derivation combining X25519 and Kyber768 shared secrets.
 */
class HkdfSha512 {
public:
    /**
     * @brief HKDF Extract + Expand in one call.
     * @param salt Optional salt value (non-secret).
     * @param ikm Input Keying Material.
     * @param info Application specific context.
     * @param okm Output Keying Material buffer.
     */
    static void derive_key(
        std::span<const uint8_t> salt,
        std::span<const uint8_t> ikm,
        std::span<const uint8_t> info,
        std::span<uint8_t> okm) noexcept;
};

} // namespace nit::crypto::osnova
