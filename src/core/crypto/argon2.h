#pragma once

#include <cstdint>
#include <span>
#include <array>
#include <vector>

namespace nit::crypto::osnova {

/**
 * @brief Argon2id Password Hashing Function.
 * Designed to resist GPU-cracking attacks using heavy memory and CPU constraints.
 * Used for deriving long-term OSNOVA master keys from user passwords.
 */
class Argon2id {
public:
    static constexpr uint32_t VERSION_NUMBER = 0x13;

    struct Config {
        uint32_t time_cost;     // Number of passes
        uint32_t memory_cost;   // Memory in KiB
        uint32_t parallelism;   // Number of lanes/threads
        uint32_t hash_len;      // Output length
    };

    Argon2id() noexcept = default;

    /**
     * @brief Computes the Argon2id hash.
     * @param out Buffer for the derived key.
     * @param password The user secret.
     * @param salt A random cryptographically secure salt.
     * @param config Tuning parameters.
     * @return true on success.
     */
    static bool hash(
        std::span<uint8_t> out,
        std::span<const uint8_t> password,
        std::span<const uint8_t> salt,
        const Config& config) noexcept;

private:
    static void fill_block(uint64_t* state, const uint64_t* ref_block, const uint64_t* next_block) noexcept;
    static void generate_addresses(uint64_t* address_block, uint32_t time_pass, uint32_t lane, 
                                   uint32_t slice, uint32_t block_count) noexcept;
    static void blake2b_long(uint8_t* out, size_t outlen, const uint8_t* in, size_t inlen) noexcept;
};

} // namespace nit::crypto::osnova
