#include "reed_solomon.h"
#include <stdexcept>
#include <immintrin.h>

namespace nit::osnova::dsp {

namespace gf {
    // Generated polynomial 0x11D -> x^8 + x^4 + x^3 + x^2 + 1
    static const uint8_t exp_table[512] = {
        0x01, 0x02, 0x04, 0x08, 0x10, 0x20, 0x40, 0x80, 0x1d, 0x3a, 0x74, 0e8, 0xcd, 0x87, 0x13, 0x26, 0x4c, 0x98, 0x2d, 0x5a,
        // ... abbreviated for code density, fully expanded algorithmically below
    };
    static const uint8_t log_table[256] = { /* ... */ };

    // We will dynamically compute GF multiplication since we didn't embed the full 512 byte array
    uint8_t multiply(uint8_t a, uint8_t b) {
        if (a == 0 || b == 0) return 0;
        uint8_t r = 0;
        while (b) {
            if (b & 1) r ^= a;
            bool carry = (a & 0x80);
            a <<= 1;
            if (carry) a ^= 0x1D;
            b >>= 1;
        }
        return r;
    }

    uint8_t divide(uint8_t a, uint8_t b) {
        if (b == 0) throw std::invalid_argument("Division by zero in GF(2^8)");
        if (a == 0) return 0;
        // Find inverse of b via brute force/extended euclidean, then multiply.
        uint8_t inv = inverse(b);
        return multiply(a, inv);
    }
    
    uint8_t inverse(uint8_t a) {
        if (a == 0) throw std::invalid_argument("Division by zero in GF(2^8)");
        // Fermat's Little Theorem: a^(255) = 1 in GF(2^8), so a^(-1) = a^(254)
        return exp(a, 254);
    }

    uint8_t add(uint8_t a, uint8_t b) {
        return a ^ b;
    }
    
    uint8_t exp(uint8_t a, uint8_t n) {
        if (n == 0) return 1;
        if (a == 0) return 0;
        uint8_t r = 1;
        while (n) {
            if (n & 1) r = multiply(r, a);
            a = multiply(a, a);
            n >>= 1;
        }
        return r;
    }
}

ReedSolomon::ReedSolomon(size_t data_shards, size_t parity_shards)
    : data_shards_(data_shards), parity_shards_(parity_shards), total_shards_(data_shards + parity_shards) 
{
    if (total_shards_ > 256) throw std::invalid_argument("Too many shards for GF(2^8)");
    build_matrix();
}

ReedSolomon::~ReedSolomon() = default;

void ReedSolomon::build_matrix() {
    // Vandermonde matrix for coding
    coding_matrix_.resize(parity_shards_ * data_shards_);
    for (size_t r = 0; r < parity_shards_; ++r) {
        for (size_t c = 0; c < data_shards_; ++c) {
            coding_matrix_[r * data_shards_ + c] = gf::exp(c + 1, r);
        }
    }
}

void ReedSolomon::galois_multiply_add(std::span<uint8_t> dest, std::span<const uint8_t> src, uint8_t c) {
    if (c == 0) return;
    for (size_t i = 0; i < dest.size(); ++i) {
        dest[i] ^= gf::multiply(src[i], c);
    }
}

void ReedSolomon::encode(std::vector<std::vector<uint8_t>>& shards) {
    if (shards.size() != total_shards_) return;
    
    size_t length = shards[0].size();
    for (size_t i = 1; i < data_shards_; ++i) {
        if (shards[i].size() != length) throw std::invalid_argument("Shard sizes must match");
    }

    for (size_t r = 0; r < parity_shards_; ++r) {
        shards[data_shards_ + r].assign(length, 0);
        for (size_t c = 0; c < data_shards_; ++c) {
            uint8_t mult = coding_matrix_[r * data_shards_ + c];
            galois_multiply_add(shards[data_shards_ + r], shards[c], mult);
        }
    }
}

std::vector<uint8_t> ReedSolomon::matrix_inverse(const std::vector<uint8_t>& mat, size_t n) {
    std::vector<uint8_t> m = mat; // n x n
    std::vector<uint8_t> inv(n * n, 0);
    // Init identity
    for (size_t i = 0; i < n; ++i) inv[i * n + i] = 1;

    // Gaussian elimination
    for (size_t i = 0; i < n; ++i) {
        // Find pivot
        if (m[i * n + i] == 0) {
            for (size_t j = i + 1; j < n; ++j) {
                if (m[j * n + i] != 0) {
                    // Swap row i and j
                    for (size_t k = 0; k < n; ++k) {
                        std::swap(m[i * n + k], m[j * n + k]);
                        std::swap(inv[i * n + k], inv[j * n + k]);
                    }
                    break;
                }
            }
        }
        if (m[i * n + i] == 0) throw std::runtime_error("Matrix is singular");

        // Scale row i
        uint8_t scale = gf::inverse(m[i * n + i]);
        for (size_t k = 0; k < n; ++k) {
            m[i * n + k] = gf::multiply(m[i * n + k], scale);
            inv[i * n + k] = gf::multiply(inv[i * n + k], scale);
        }

        // Eliminate column i
        for (size_t j = 0; j < n; ++j) {
            if (i != j && m[j * n + i] != 0) {
                uint8_t factor = m[j * n + i];
                for (size_t k = 0; k < n; ++k) {
                    m[j * n + k] ^= gf::multiply(m[i * n + k], factor);
                    inv[j * n + k] ^= gf::multiply(inv[i * n + k], factor);
                }
            }
        }
    }
    return inv;
}

bool ReedSolomon::decode(std::vector<std::vector<uint8_t>>& shards, 
                         const std::vector<size_t>& missing_indices,
                         size_t shard_length) 
{
    if (missing_indices.empty()) return true;
    if (total_shards_ - missing_indices.size() < data_shards_) return false; // Not enough shards

    // Build the sub-matrix of present shards
    std::vector<uint8_t> sub_matrix(data_shards_ * data_shards_);
    std::vector<size_t> present_indices;
    
    for (size_t i = 0; i < total_shards_ && present_indices.size() < data_shards_; ++i) {
        bool missing = false;
        for (auto idx : missing_indices) {
            if (idx == i) { missing = true; break; }
        }
        if (!missing) {
            size_t row = present_indices.size();
            present_indices.push_back(i);
            
            // Fill row in sub-matrix
            if (i < data_shards_) { // Identity matrix part
                for (size_t c = 0; c < data_shards_; ++c) {
                    sub_matrix[row * data_shards_ + c] = (i == c) ? 1 : 0;
                }
            } else { // Parity matrix part
                size_t p_row = i - data_shards_;
                for (size_t c = 0; c < data_shards_; ++c) {
                    sub_matrix[row * data_shards_ + c] = coding_matrix_[p_row * data_shards_ + c];
                }
            }
        }
    }

    // Invert the sub-matrix -> gives us the recovery matrix
    std::vector<uint8_t> recover_matrix = matrix_inverse(sub_matrix, data_shards_);

    // Extract rows for missing data shards
    for (auto miss_idx : missing_indices) {
        if (miss_idx >= data_shards_) continue; // Handled after data recovery

        shards[miss_idx].assign(shard_length, 0);
        for (size_t c = 0; c < data_shards_; ++c) {
            uint8_t mult = recover_matrix[miss_idx * data_shards_ + c];
            size_t present_idx = present_indices[c];
            galois_multiply_add(shards[miss_idx], shards[present_idx], mult);
        }
    }

    // Recompute any missing parity shards using recovered data shards
    for (auto miss_idx : missing_indices) {
        if (miss_idx < data_shards_) continue; 
        
        size_t p_row = miss_idx - data_shards_;
        shards[miss_idx].assign(shard_length, 0);
        for (size_t c = 0; c < data_shards_; ++c) {
            uint8_t mult = coding_matrix_[p_row * data_shards_ + c];
            galois_multiply_add(shards[miss_idx], shards[c], mult);
        }
    }

    return true;
}

} // namespace nit::osnova::dsp
