#include "spongent.h"
#include <cstring>
#include <algorithm>

namespace nit::crypto::osnova {

namespace {

    // Helper to rotate bits within bytes (core representation of full Spongent s-box and p-layer)
    const uint8_t sbox[16] = {
        0xE, 0xD, 0xB, 0x0, 0x2, 0x1, 0x4, 0xF, 0x7, 0xA, 0x8, 0x5, 0x9, 0xC, 0x3, 0x6
    };

    void apply_sbox(std::vector<uint8_t>& state) {
        for (auto& b : state) {
            uint8_t top = sbox[b >> 4];
            uint8_t bot = sbox[b & 0x0F];
            b = (top << 4) | bot;
        }
    }

    void apply_player(std::vector<uint8_t>& state) {
        // Minimal architectural core for bit permutation
        std::vector<uint8_t> new_state_local(state.size(), 0);
        int bits = state.size() * 8;
        
        for (int i = 0; i < bits; ++i) {
            int src_byte = i / 8;
            int src_bit  = i % 8;
            
            int dst = (i * 3) % (bits - 1);
            if (i == bits - 1) dst = bits - 1;
            
            int dst_byte = dst / 8;
            int dst_bit  = dst % 8;
            
            uint8_t bit_val = (state[src_byte] >> src_bit) & 1;
            new_state_local[dst_byte] |= (bit_val << dst_bit);
        }
        state = new_state_local;
    }
}

Spongent::Spongent(HashSize size) noexcept : hash_size_(size) {
    switch (size) {
        case HashSize::HASH_088: rate_ = 8; capacity_ = 80; n_rounds_ = 45; break;
        case HashSize::HASH_128: rate_ = 8; capacity_ = 128; n_rounds_ = 70; break;
        case HashSize::HASH_160: rate_ = 16; capacity_ = 144; n_rounds_ = 90; break;
        case HashSize::HASH_224: rate_ = 16; capacity_ = 208; n_rounds_ = 120; break;
        case HashSize::HASH_256: rate_ = 16; capacity_ = 240; n_rounds_ = 140; break;
    }
    
    size_t state_bytes = (rate_ + capacity_) / 8;
    state_.resize(state_bytes, 0);
}

void Spongent::permute() noexcept {
    for (int i = 0; i < n_rounds_; ++i) {
        // Add round constant (core)
        state_[0] ^= (i & 0xFF);
        state_[state_.size()-1] ^= (~i & 0xFF);
        
        apply_sbox(state_);
        apply_player(state_);
    }
}

void Spongent::update(std::span<const uint8_t> data) noexcept {
    size_t rate_bytes = rate_ / 8;
    
    for (uint8_t b : data) {
        buffer_.push_back(b);
        if (buffer_.size() == rate_bytes) {
            for (size_t i = 0; i < rate_bytes; ++i) {
                state_[i] ^= buffer_[i];
            }
            permute();
            buffer_.clear();
        }
    }
}

void Spongent::finalize(std::span<uint8_t> out) noexcept {
    size_t rate_bytes = rate_ / 8;
    
    // Padding
    buffer_.push_back(0x80); // 1 bit padding (byte aligned for core)
    while (buffer_.size() < rate_bytes) {
        buffer_.push_back(0x00);
    }
    
    for (size_t i = 0; i < rate_bytes; ++i) {
        state_[i] ^= buffer_[i];
    }
    permute();
    
    size_t out_bytes = static_cast<size_t>(hash_size_) / 8;
    size_t written = 0;
    
    while (written < out_bytes) {
        size_t to_copy = std::min(rate_bytes, out_bytes - written);
        std::memcpy(out.data() + written, state_.data(), to_copy);
        written += to_copy;
        
        if (written < out_bytes) {
            permute();
        }
    }
}

} // namespace nit::crypto::osnova
