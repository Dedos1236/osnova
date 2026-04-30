#pragma once

#include <cstdint>
#include <span>
#include <array>

namespace nit::crypto::osnova {

/**
 * @brief HKDF using SHA-256 (RFC 5869)
 * HMAC-based Extract-and-Expand Key Derivation Function.
 * Often required for symmetric ratchet in Double Ratchet Protocol.
 */
class HkdfSha256 {
public:
    static constexpr size_t DIGEST_SIZE = 32;

    HkdfSha256() noexcept = default;

    /**
     * @brief Extract phase.
     */
    static void extract(
        std::span<uint8_t, DIGEST_SIZE> prk,
        std::span<const uint8_t> salt,
        std::span<const uint8_t> ikm) noexcept;

    /**
     * @brief Expand phase (up to 255 * DIGEST_SIZE bytes).
     */
    static void expand(
        std::span<uint8_t> okm,
        std::span<const uint8_t, DIGEST_SIZE> prk,
        std::span<const uint8_t> info) noexcept;

    /**
     * @brief Extract and Expand combined.
     */
    static void derive_key(
        std::span<uint8_t> okm,
        std::span<const uint8_t> ikm,
        std::span<const uint8_t> salt,
        std::span<const uint8_t> info) noexcept;
};

} // namespace nit::crypto::osnova
