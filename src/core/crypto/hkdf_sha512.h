#pragma once

#include <cstdint>
#include <span>
#include <vector>

namespace nit::crypto::osnova {

/**
 * @brief HMAC-based Extract-and-Expand Key Derivation Function (HKDF) using SHA-512.
 * RFC 5869.
 */
class HkdfSha512 {
public:
    static constexpr size_t HASH_LEN = 64;

    static void extract(
        std::span<uint8_t, HASH_LEN> prk,
        std::span<const uint8_t> salt,
        std::span<const uint8_t> ikm) noexcept;

    static void expand(
        std::span<uint8_t> okm,
        std::span<const uint8_t, HASH_LEN> prk,
        std::span<const uint8_t> info) noexcept;

    static void derive_key(
        std::span<uint8_t> okm,
        std::span<const uint8_t> ikm,
        std::span<const uint8_t> salt,
        std::span<const uint8_t> info) noexcept;
};

} // namespace nit::crypto::osnova
