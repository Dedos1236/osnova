#pragma once

#include <cstdint>
#include <span>

namespace nit::crypto::osnova {

/**
 * @brief SHA-256 Cryptographic Hash Function (FIPS 180-4).
 * Standardized hash algorithm for broad usage outside of PQC.
 */
class Sha256 {
public:
    static constexpr size_t DIGEST_SIZE = 32;

    Sha256() noexcept;

    void update(std::span<const uint8_t> data) noexcept;
    void finalize(std::span<uint8_t, DIGEST_SIZE> digest) noexcept;

private:
    void process_block(const uint8_t* block) noexcept;

    uint32_t state_[8];
    uint64_t total_length_;
    uint8_t buffer_[64];
    size_t buffer_length_;
};

} // namespace nit::crypto::osnova
