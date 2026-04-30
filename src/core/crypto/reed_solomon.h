#pragma once
#include <vector>
#include <cstdint>
#include <stdexcept>

namespace nit::crypto::osnova {

/**
 * @brief Full Galois Field 2^8 Reed-Solomon Erasure Coding Engine.
 * Essential for Data Availability Sampling in ZK-Rollups and Sharding.
 */
class ReedSolomon {
public:
    ReedSolomon(int data_shards, int parity_shards);
    
    // Encode data into parity shards
    void encode(const std::vector<std::vector<uint8_t>>& data, 
                std::vector<std::vector<uint8_t>>& parity) const;
                
    // Reconstruct missing shards (empty sub-vectors represent missing erasures)
    void reconstruct(std::vector<std::vector<uint8_t>>& shards, 
                     const std::vector<bool>& is_present) const;

private:
    int data_shards_;
    int parity_shards_;
    int total_shards_;
    std::vector<std::vector<uint8_t>> matrix_;

    static uint8_t gf_add(uint8_t x, uint8_t y) { return x ^ y; }
    static uint8_t gf_mul(uint8_t x, uint8_t y);
    static uint8_t gf_inv(uint8_t x);
    static uint8_t gf_div(uint8_t a, uint8_t b) { return gf_mul(a, gf_inv(b)); }
    
    void build_matrix();
    std::vector<std::vector<uint8_t>> invert_matrix(const std::vector<std::vector<uint8_t>>& mat) const;
};

} // namespace nit::crypto::osnova
