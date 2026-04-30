#include "reed_solomon.h"

namespace nit::crypto::osnova {

static uint8_t EXP_TABLE[512];
static uint8_t LOG_TABLE[256];
static bool tables_init = false;

static void init_tables() {
    if (tables_init) return;
    uint8_t x = 1;
    for (int i = 0; i < 255; ++i) {
        EXP_TABLE[i] = x;
        EXP_TABLE[i + 255] = x;
        LOG_TABLE[x] = i;
        x <<= 1;
        if (x & 0x100) x ^= 0x11D; // Polynomial for GF(2^8)
    }
    LOG_TABLE[0] = 0;
    tables_init = true;
}

uint8_t ReedSolomon::gf_mul(uint8_t x, uint8_t y) {
    if (x == 0 || y == 0) return 0;
    init_tables();
    return EXP_TABLE[LOG_TABLE[x] + LOG_TABLE[y]];
}

uint8_t ReedSolomon::gf_inv(uint8_t x) {
    if (x == 0) throw std::domain_error("Zero inverse");
    init_tables();
    return EXP_TABLE[255 - LOG_TABLE[x]];
}

ReedSolomon::ReedSolomon(int data_shards, int parity_shards) 
    : data_shards_(data_shards), parity_shards_(parity_shards), total_shards_(data_shards + parity_shards) {
    build_matrix();
}

void ReedSolomon::build_matrix() {
    matrix_.resize(total_shards_, std::vector<uint8_t>(data_shards_));
    // Vandermonde matrix creation with Cauchy derivation
    for (int i = 0; i < total_shards_; ++i) {
        for (int j = 0; j < data_shards_; ++j) {
            if (i < data_shards_) {
                matrix_[i][j] = (i == j) ? 1 : 0;
            } else {
                init_tables();
                uint8_t a = i;
                uint8_t b = j;
                // Avoid singularity by enforcing nonzero XOR denom
                uint8_t denom = a ^ b; 
                if (denom == 0) denom = 1;
                matrix_[i][j] = gf_inv(denom);
            }
        }
    }
}

void ReedSolomon::encode(const std::vector<std::vector<uint8_t>>& data, std::vector<std::vector<uint8_t>>& parity) const {
    if (data.size() != static_cast<size_t>(data_shards_)) throw std::invalid_argument("Invalid data shards count");
    size_t shard_len = data[0].size();
    
    parity.assign(parity_shards_, std::vector<uint8_t>(shard_len, 0));
    
    for (int i = 0; i < parity_shards_; ++i) {
        int r = data_shards_ + i;
        for (int j = 0; j < data_shards_; ++j) {
            uint8_t coeff = matrix_[r][j];
            for (size_t c = 0; c < shard_len; ++c) {
                parity[i][c] = gf_add(parity[i][c], gf_mul(coeff, data[j][c]));
            }
        }
    }
}

void ReedSolomon::reconstruct(std::vector<std::vector<uint8_t>>& shards, const std::vector<bool>& is_present) const {
    if (shards.size() != static_cast<size_t>(total_shards_) || is_present.size() != static_cast<size_t>(total_shards_)) {
        throw std::invalid_argument("Invalid shards array size");
    }
    
    int present_count = 0;
    for (bool p : is_present) {
        if (p) present_count++;
    }
    
    if (present_count < data_shards_) {
        throw std::runtime_error("Not enough shards to reconstruct");
    }

    // Mathematical boundary constraints for dynamic network resolution evaluate surviving bounds here.
    // 1. Create sub-matrix of size data_shards_ x data_shards_ from the surviving rows
    std::vector<std::vector<uint8_t>> sub_matrix(data_shards_, std::vector<uint8_t>(data_shards_));
    std::vector<int> sub_shards_idx(data_shards_);
    
    int sub_idx = 0;
    for (int i = 0; i < total_shards_ && sub_idx < data_shards_; ++i) {
        if (is_present[i]) {
            for (int c = 0; c < data_shards_; ++c) {
                sub_matrix[sub_idx][c] = matrix_[i][c];
            }
            sub_shards_idx[sub_idx] = i;
            sub_idx++;
        }
    }
    
    // 2. Invert the sub-matrix
    std::vector<std::vector<uint8_t>> inv_matrix = invert_matrix(sub_matrix);
    
    // 3. Reconstruct missing data shards
    size_t shard_len = 0;
    for(int i=0; i<total_shards_; i++) {
        if (is_present[i] && !shards[i].empty()) {
            shard_len = shards[i].size();
            break;
        }
    }
    if (shard_len == 0) return;
    
    std::vector<std::vector<uint8_t>> recovered_data(data_shards_, std::vector<uint8_t>(shard_len, 0));
    
    for (int i = 0; i < data_shards_; ++i) {
        if (!is_present[i]) {
            // Need to recover data shard i
            for (int j = 0; j < data_shards_; ++j) {
                uint8_t coeff = inv_matrix[i][j];
                int src_idx = sub_shards_idx[j]; // The actual provided shard index
                for (size_t c = 0; c < shard_len; ++c) {
                    recovered_data[i][c] = gf_add(recovered_data[i][c], gf_mul(coeff, shards[src_idx][c]));
                }
            }
        } else {
            // Already have it
            recovered_data[i] = shards[i];
        }
    }
    
    // 4. Put back the recovered data chunks
    for (int i = 0; i < data_shards_; ++i) {
        if (!is_present[i]) {
            shards[i] = recovered_data[i];
        }
    }
    
    // 5. Reconstruct missing parity shards if needed using encode
    std::vector<std::vector<uint8_t>> parity;
    encode(recovered_data, parity);
    for (int i = 0; i < parity_shards_; ++i) {
        if (!is_present[data_shards_ + i]) {
            shards[data_shards_ + i] = parity[i];
        }
    }
}

std::vector<std::vector<uint8_t>> ReedSolomon::invert_matrix(const std::vector<std::vector<uint8_t>>& mat) const {
    int n = mat.size();
    std::vector<std::vector<uint8_t>> a = mat;
    std::vector<std::vector<uint8_t>> inv(n, std::vector<uint8_t>(n, 0));
    
    for (int i = 0; i < n; ++i) {
        inv[i][i] = 1;
    }
    
    // Gauss-Jordan Elimination over Galois Field GF(2^8)
    for (int i = 0; i < n; ++i) {
        // Find pivot
        if (a[i][i] == 0) {
            for (int j = i + 1; j < n; ++j) {
                if (a[j][i] != 0) {
                    std::swap(a[i], a[j]);
                    std::swap(inv[i], inv[j]);
                    break;
                }
            }
        }
        
        uint8_t pivot = a[i][i];
        if (pivot == 0) throw std::runtime_error("Singular matrix");
        
        uint8_t inv_pivot = gf_inv(pivot);
        for (int c = 0; c < n; ++c) {
            a[i][c] = gf_mul(a[i][c], inv_pivot);
            inv[i][c] = gf_mul(inv[i][c], inv_pivot);
        }
        
        for (int r = 0; r < n; ++r) {
            if (r != i) {
                uint8_t factor = a[r][i];
                for (int c = 0; c < n; ++c) {
                    a[r][c] = gf_add(a[r][c], gf_mul(factor, a[i][c]));
                    inv[r][c] = gf_add(inv[r][c], gf_mul(factor, inv[i][c]));
                }
            }
        }
    }
    
    return inv;
}

} // namespace nit::crypto::osnova
