#pragma once

#include <cstdint>
#include <span>
#include <vector>

namespace nit::crypto::osnova {

/**
 * @brief SM3 Cryptographic Hash Algorithm.
 * Chinese Commercial Cryptography Standard (GB/T 32905-2016).
 * Produces a 256-bit hash. Used for interoperability in certain regulatory paths.
 */
class Sm3 {
public:
    static constexpr size_t DIGEST_SIZE = 32;
    static constexpr size_t BLOCK_SIZE = 64;

    Sm3() noexcept;

    void update(std::span<const uint8_t> data) noexcept;
    void finalize(std::span<uint8_t, DIGEST_SIZE> out) noexcept;

    // One-shot compute
    static void compute(std::span<uint8_t, DIGEST_SIZE> out, std::span<const uint8_t> data) noexcept;

private:
    uint32_t state_[8];
    uint64_t bit_count_;
    uint8_t buffer_[BLOCK_SIZE];
    size_t buffer_len_;

    void transform() noexcept;
};

} // namespace nit::crypto::osnova
