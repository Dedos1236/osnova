#pragma once

#include <cstdint>
#include <span>
#include <array>

namespace nit::crypto::osnova {

/**
 * @brief Keccak-based Hash and Extendable-Output Functions (FIPS 202).
 * Includes SHA3-256, SHA3-512, SHAKE128, and SHAKE256.
 * Mandatory for Kyber / ML-KEM internal PRNG and hashing.
 */
class Sha3 {
public:
    static constexpr size_t KECCAK_STATE_BYTES = 200; // 1600 bits
    static constexpr size_t KECCAK_STATE_WORDS = 25;  // 25 * 64 bits

    Sha3() noexcept;

    /**
     * @brief Raw Keccak-f[1600] permutation.
     * @param state The 1600-bit state (25 uint64_t).
     */
    static void keccak_f1600(uint64_t state[KECCAK_STATE_WORDS]) noexcept;

    enum class Type {
        SHA3_256,
        SHA3_512,
        SHAKE128,
        SHAKE256
    };

    /**
     * @brief Initialize context for specific SHA3/SHAKE variant.
     */
    void init(Type type) noexcept;

    /**
     * @brief Ingest input data into the sponge.
     */
    void update(std::span<const uint8_t> data) noexcept;

    /**
     * @brief Finalize and squeeze fixed-length output (for SHA3).
     */
    void finalize(std::span<uint8_t> digest) noexcept;

    /**
     * @brief Squeeze arbitrary length output (for SHAKE).
     */
    void squeeze(std::span<uint8_t> out) noexcept;

private:
    void absorb_block(const uint8_t* in) noexcept;
    void squeeze_block(uint8_t* out) noexcept;

    uint64_t state_[KECCAK_STATE_WORDS];
    uint32_t rate_bytes_;
    uint32_t capacity_bytes_;
    uint32_t byte_io_index_;
    uint8_t  suffix_;
    bool     absorbing_;
};

} // namespace nit::crypto::osnova
