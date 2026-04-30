#pragma once

#include <cstdint>
#include <span>
#include <array>

namespace nit::crypto::osnova {

/**
 * @brief SHA-512 Cryptographic Hash Function.
 * Fully compliant with FIPS 180-4.
 */
class Sha512 {
public:
    static constexpr size_t DIGEST_SIZE = 64;
    static constexpr size_t BLOCK_SIZE = 128;

    Sha512() noexcept;
    ~Sha512();

    Sha512(const Sha512&) = delete;
    Sha512& operator=(const Sha512&) = delete;

    /**
     * @brief Feeds a chunk of data into the hash state.
     */
    void update(std::span<const uint8_t> data) noexcept;

    /**
     * @brief Finalizes the hash state and outputs the digest.
     */
    void finalize(std::span<uint8_t, DIGEST_SIZE> digest) noexcept;

    /**
     * @brief Helper for one-shot hashing.
     */
    static void hash(std::span<const uint8_t> data, std::span<uint8_t, DIGEST_SIZE> digest) noexcept;

private:
    uint64_t state_[8];
    uint64_t bit_count_[2]; // [0] low, [1] high
    uint8_t  buffer_[BLOCK_SIZE];

    void transform(const uint8_t* block) noexcept;
};

} // namespace nit::crypto::osnova
