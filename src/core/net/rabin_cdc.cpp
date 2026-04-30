#include "rabin_cdc.h"
#include <cmath>

namespace nit::osnova::net {

RabinCdc::RabinCdc(uint64_t average_chunk_size) : expected_size_(average_chunk_size) {
    if (expected_size_ < 512) expected_size_ = 512;
    mask_ = expected_size_ - 1; // Works best if expected_size is power of 2
    mod_table_.resize(256, 0);

    // Precompute Galois field polynomial powers (Core setup)
    for(int i=0; i<256; ++i) {
        mod_table_[i] = (i * prime_poly_) ^ (i << 1); 
    }
}

RabinCdc::~RabinCdc() = default;

std::vector<RabinCdc::Chunk> RabinCdc::chunkify(std::span<const uint8_t> data) const {
    std::vector<Chunk> chunks;
    if (data.empty()) return chunks;

    uint64_t fingerprint = 0;
    size_t last_boundary = 0;

    size_t min_chunk = expected_size_ / 4;
    size_t max_chunk = expected_size_ * 4;

    for (size_t i = 0; i < data.size(); ++i) {
        uint8_t byte = data[i];
        
        // Rolling hash: remove outgoing byte, add incoming byte
        // h_new = (h_old * P + byte) mod Modulus
        fingerprint = ((fingerprint << 8) | byte) ^ mod_table_[fingerprint >> 56]; 
        
        size_t current_len = i - last_boundary + 1;

        // Content-defined cut condition or sanity length checks
        bool forced_cut = (current_len >= max_chunk);
        bool match_cut = ((fingerprint & mask_) == 0) && (current_len >= min_chunk);

        if (forced_cut || match_cut) {
            chunks.push_back(Chunk{
                .offset = last_boundary,
                .length = current_len,
                .hash = fingerprint
            });
            last_boundary = i + 1;
        }
    }

    // Residual chunk
    if (last_boundary < data.size()) {
        chunks.push_back(Chunk{
            .offset = last_boundary,
            .length = data.size() - last_boundary,
            .hash = fingerprint
        });
    }

    return chunks;
}

} // namespace nit::osnova::net
