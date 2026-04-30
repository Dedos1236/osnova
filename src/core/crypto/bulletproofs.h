#pragma once

#include <cstdint>
#include <span>
#include <vector>

namespace nit::crypto::osnova {

/**
 * @brief Bulletproofs Zero-Knowledge Range Proofs.
 * Enables proving that a committed value (e.g. account balance, message score) 
 * lies within a certain range [0, 2^n - 1] without revealing the value itself.
 */
class Bulletproofs {
public:
    static constexpr size_t COMMITMENT_SIZE = 32;
    static constexpr size_t BLINDING_FACTOR_SIZE = 32;
    static constexpr size_t MAX_RANGE_BITS = 64;

    struct Proof {
        std::vector<uint8_t> V; // Commitment to the value
        std::vector<uint8_t> A; // Commitment to bits
        std::vector<uint8_t> S; // Commitment to blinding factors
        std::vector<uint8_t> T1;
        std::vector<uint8_t> T2;
        std::vector<uint8_t> tx;
        std::vector<uint8_t> th;
        std::vector<uint8_t> e;
        std::vector<uint8_t> a, b;
        std::vector<std::vector<uint8_t>> L, R;
    };

    /**
     * @brief Generate a Pedersen Commitment to a value.
     */
    static void generate_commitment(
        std::span<uint8_t, COMMITMENT_SIZE> commitment,
        std::span<const uint8_t, BLINDING_FACTOR_SIZE> blinding_factor,
        uint64_t value) noexcept;

    /**
     * @brief Generate a range proof for a value.
     */
    static bool prove_range(
        Proof& proof,
        uint64_t value,
        std::span<const uint8_t, BLINDING_FACTOR_SIZE> blinding_factor,
        size_t bit_length) noexcept;

    /**
     * @brief Verify a range proof against a commitment.
     */
    static bool verify_range(
        const Proof& proof,
        std::span<const uint8_t, COMMITMENT_SIZE> commitment,
        size_t bit_length) noexcept;

    /**
     * @brief Serialize a proof to bytes.
     */
    static std::vector<uint8_t> serialize(const Proof& proof) noexcept;

    /**
     * @brief Deserialize a proof from bytes.
     */
    static bool deserialize(Proof& proof, std::span<const uint8_t> data) noexcept;
};

} // namespace nit::crypto::osnova
