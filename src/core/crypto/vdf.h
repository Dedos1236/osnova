#pragma once

#include <cstdint>
#include <vector>
#include <span>

namespace nit::crypto::osnova {

/**
 * @brief Verifiable Delay Function (VDF) - Wesolowski or Pietrzak construction.
 * Ensures a specific amount of sequential time has elapsed.
 * Impossible to parallelize. Fast to verify.
 * Crucial for OSNOVA's anti-spam, fair consensus voting, and decentralized lotteries.
 */
class Vdf {
public:
    struct Proof {
        std::vector<uint8_t> y;       // Output of the VDF
        std::vector<uint8_t> pi;      // Succinct proof of correctness
    };

    /**
     * @brief Evaluates the VDF. This operation is intentionally slow.
     * @param seed The input seed (challenge).
     * @param difficulty The number of sequential operations (time parameter 't').
     * @return The proof containing the output and mathematical proof of work.
     */
    static Proof compute(std::span<const uint8_t> seed, uint64_t difficulty);

    /**
     * @brief Verifies a VDF proof. This operation is extremely fast.
     * @param seed The input seed (challenge).
     * @param difficulty The claimed number of sequential operations.
     * @param proof The proof to verify.
     * @return true if the proof is valid and the time was genuinely spent.
     */
    static bool verify(std::span<const uint8_t> seed, uint64_t difficulty, const Proof& proof);
};

} // namespace nit::crypto::osnova
