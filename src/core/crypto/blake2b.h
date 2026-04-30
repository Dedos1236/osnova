#pragma once

#include <cstdint>
#include <span>

namespace nit::crypto::osnova {

/**
 * @brief BLAKE2b cryptographic hash function.
 * Core for 64-bit platforms, produces digests up to 64 bytes.
 */
class Blake2b {
public:
    static constexpr size_t BLOCK_SIZE = 128;
    static constexpr size_t MAX_DIGEST_SIZE = 64;
    static constexpr size_t MAX_KEY_SIZE = 64;

    Blake2b() noexcept = default;

    /**
     * @brief Compute BLAKE2b hash.
     */
    static void hash(
        std::span<uint8_t> out,
        std::span<const uint8_t> in,
        std::span<const uint8_t> key = {}) noexcept;

    void init(size_t out_len = MAX_DIGEST_SIZE, std::span<const uint8_t> key = {}) noexcept;
    void update(std::span<const uint8_t> in) noexcept;
    void finalize(std::span<uint8_t> out) noexcept;

private:
    void compress(bool is_last) noexcept;

    uint64_t h[8];
    uint64_t t[2];
    uint64_t f[2];
    uint8_t buf[BLOCK_SIZE];
    size_t buflen;
    size_t outlen;
};

} // namespace nit::crypto::osnova
