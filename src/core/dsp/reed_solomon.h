#pragma once

#include <vector>
#include <cstdint>
#include <span>

namespace nit::osnova::dsp {

/**
 * @brief Reed-Solomon Forward Error Correction (FEC).
 * Native OSNOVA DSP component. Fully implemented Galois Field (GF(2^8)) arithmetic.
 * Generates parity shards from data shards and completely reconstructs lost streams
 * over high-packet-loss UDP transmission, without requesting retransmission.
 */
class ReedSolomon {
public:
    ReedSolomon(size_t data_shards, size_t parity_shards);
    ~ReedSolomon();

    /**
     * @brief Generates parity shards from given data shards.
     * @param shards Must contain total_shards (data + parity) buffers all of equal length.
     *               The first `data_shards` must be filled. The remaining will be written to.
     */
    void encode(std::vector<std::vector<uint8_t>>& shards);

    /**
     * @brief Reconstructs missing shards (both data and parity).
     * @param shards The total array of shards. Missing shards should be empty vectors.
     * @param missing_indices Array of indices representing which shards are missing/empty.
     * @param shard_length The expected length of every shard.
     * @return true if successfully decoded, false if not enough shards.
     */
    bool decode(std::vector<std::vector<uint8_t>>& shards, 
                const std::vector<size_t>& missing_indices,
                size_t shard_length);

private:
    size_t data_shards_;
    size_t parity_shards_;
    size_t total_shards_;

    std::vector<uint8_t> coding_matrix_; // parity_shards_ x data_shards_

    void build_matrix();
    void galois_multiply_add(std::span<uint8_t> dest, std::span<const uint8_t> src, uint8_t c);
    
    // Matrix math in GF(2^8)
    std::vector<uint8_t> matrix_multiply(const std::vector<uint8_t>& a, size_t a_rows, size_t a_cols,
                                         const std::vector<uint8_t>& b, size_t b_cols);
    std::vector<uint8_t> matrix_inverse(const std::vector<uint8_t>& mat, size_t n);
};

// --- Galois Field Tables ---
namespace gf {
    uint8_t multiply(uint8_t x, uint8_t y);
    uint8_t divide(uint8_t x, uint8_t y);
    uint8_t inverse(uint8_t x);
    uint8_t add(uint8_t x, uint8_t y);
    uint8_t exp(uint8_t a, uint8_t n);
} // namespace gf

} // namespace nit::osnova::dsp
