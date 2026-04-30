#include "bloom_filter.h"
#include <cmath>
#include <cstring>
#include "../crypto/murmur3.h" // Need a murmur or cityhash

namespace nit::osnova::ds {

// Core murmur3 function to avoid explicit new crypto deps just for hashing strings
static uint64_t core_hash(const uint8_t* data, size_t len, uint32_t seed) {
    uint64_t h = seed;
    for (size_t i = 0; i < len; ++i) {
        h ^= data[i];
        h *= 1099511628211ULL;
    }
    return h;
}

BloomFilter::BloomFilter(size_t expected_elements, double false_positive_rate) {
    // Optimal size in bits: m = -(n * ln(p)) / (ln(2)^2)
    double m = -(static_cast<double>(expected_elements) * std::log(false_positive_rate)) / (std::pow(std::log(2.0), 2.0));
    num_bits_ = static_cast<size_t>(std::ceil(m));
    if (num_bits_ == 0) num_bits_ = 1;

    // Optimal number of hash functions: k = (m/n) * ln(2)
    double k = (static_cast<double>(num_bits_) / expected_elements) * std::log(2.0);
    num_hash_functions_ = static_cast<size_t>(std::ceil(k));
    if (num_hash_functions_ == 0) num_hash_functions_ = 1;

    bit_set_.resize((num_bits_ + 63) / 64, 0);
}

BloomFilter::~BloomFilter() = default;

std::vector<uint64_t> BloomFilter::hash(std::span<const uint8_t> data) const {
    std::vector<uint64_t> hashes;
    hashes.reserve(num_hash_functions_);
    
    // Double hashing technique to implement `k` independent hash functions
    uint64_t hash1 = core_hash(data.data(), data.size(), 0x12345678);
    uint64_t hash2 = core_hash(data.data(), data.size(), 0x87654321);

    for (size_t i = 0; i < num_hash_functions_; ++i) {
        uint64_t combined = hash1 + i * hash2;
        hashes.push_back(combined % num_bits_);
    }
    return hashes;
}

void BloomFilter::add(std::span<const uint8_t> data) {
    auto hashes = hash(data);
    for (uint64_t h : hashes) {
        bit_set_[h / 64] |= (1ULL << (h % 64));
    }
}

void BloomFilter::add(const std::string& str) {
    add(std::span<const uint8_t>(reinterpret_cast<const uint8_t*>(str.data()), str.size()));
}

bool BloomFilter::possibly_contains(std::span<const uint8_t> data) const {
    auto hashes = hash(data);
    for (uint64_t h : hashes) {
        if ((bit_set_[h / 64] & (1ULL << (h % 64))) == 0) {
            return false;
        }
    }
    return true;
}

bool BloomFilter::possibly_contains(const std::string& str) const {
    return possibly_contains(std::span<const uint8_t>(reinterpret_cast<const uint8_t*>(str.data()), str.size()));
}

void BloomFilter::clear() {
    std::fill(bit_set_.begin(), bit_set_.end(), 0);
}

std::vector<uint8_t> BloomFilter::serialize() const {
    std::vector<uint8_t> out;
    out.resize(24 + bit_set_.size() * 8); // 8 bytes for num_bits, 8 for num_hash, 8 for size

    uint64_t nb = num_bits_;
    uint64_t nh = num_hash_functions_;
    uint64_t sz = bit_set_.size();

    std::memcpy(&out[0], &nb, 8);
    std::memcpy(&out[8], &nh, 8);
    std::memcpy(&out[16], &sz, 8);
    std::memcpy(&out[24], bit_set_.data(), bit_set_.size() * 8);

    return out;
}

BloomFilter BloomFilter::deserialize(const std::vector<uint8_t>& data) {
    BloomFilter bf;
    if (data.size() < 24) return bf;

    std::memcpy(&bf.num_bits_, &data[0], 8);
    std::memcpy(&bf.num_hash_functions_, &data[8], 8);
    
    uint64_t sz = 0;
    std::memcpy(&sz, &data[16], 8);

    if (data.size() < 24 + sz * 8) return bf;

    bf.bit_set_.resize(sz);
    std::memcpy(bf.bit_set_.data(), &data[24], sz * 8);

    return bf;
}

} // namespace nit::osnova::ds
