#include "cuckoo_filter.h"
#include <cmath>
#include <cstdlib>

namespace nit::osnova::ds {

// Core hash functions
static uint64_t core_hash(const uint8_t* data, size_t len, uint32_t seed) {
    uint64_t h = seed;
    for (size_t i = 0; i < len; ++i) {
        h ^= data[i];
        h *= 1099511628211ULL;
    }
    return h;
}

static uint64_t core_hash_int(uint64_t val) {
    val ^= val >> 33;
    val *= 0xff51afd7ed558ccdULL;
    val ^= val >> 33;
    val *= 0xc4ceb9fe1a85ec53ULL;
    val ^= val >> 33;
    return val;
}

CuckooFilter::CuckooFilter(size_t max_capacity) {
    // Determine smallest power of 2 buckets that can hold max_capacity
    size_t b = max_capacity / Bucket::BUCKET_SIZE;
    if (b == 0) b = 1;
    num_buckets_ = 1;
    while (num_buckets_ < b) num_buckets_ <<= 1;
    buckets_.resize(num_buckets_);
}

CuckooFilter::~CuckooFilter() = default;

uint16_t CuckooFilter::get_fingerprint(std::span<const uint8_t> data) const {
    uint64_t h = core_hash(data.data(), data.size(), 0xFACEB00C);
    uint16_t fp = h & 0xFFFF;
    if (fp == 0) fp = 1; // 0 refers to empty
    return fp;
}

size_t CuckooFilter::hash_index(std::span<const uint8_t> data) const {
    uint64_t h = core_hash(data.data(), data.size(), 0xBADF00D);
    return h & (num_buckets_ - 1); // Fast modulo power of 2
}

size_t CuckooFilter::alt_index(size_t index, uint16_t fingerprint) const {
    uint64_t hash = core_hash_int(fingerprint);
    return (index ^ hash) & (num_buckets_ - 1);
}

bool CuckooFilter::add(std::span<const uint8_t> data) {
    uint16_t fp = get_fingerprint(data);
    size_t i1 = hash_index(data);
    size_t i2 = alt_index(i1, fp);

    // Try to place in bucket 1
    for (size_t i = 0; i < Bucket::BUCKET_SIZE; ++i) {
        if (buckets_[i1].fingerprints[i] == 0) {
            buckets_[i1].fingerprints[i] = fp;
            count_++;
            return true;
        }
    }

    // Try to place in bucket 2
    for (size_t i = 0; i < Bucket::BUCKET_SIZE; ++i) {
        if (buckets_[i2].fingerprints[i] == 0) {
            buckets_[i2].fingerprints[i] = fp;
            count_++;
            return true;
        }
    }

    // Relocate via kicks
    size_t current_idx = (rand() % 2 == 0) ? i1 : i2;
    for (size_t kick = 0; kick < MAX_KICKS; ++kick) {
        size_t rand_slot = rand() % Bucket::BUCKET_SIZE;
        uint16_t old_fp = buckets_[current_idx].fingerprints[rand_slot];
        buckets_[current_idx].fingerprints[rand_slot] = fp;

        fp = old_fp;
        current_idx = alt_index(current_idx, fp);

        for (size_t i = 0; i < Bucket::BUCKET_SIZE; ++i) {
            if (buckets_[current_idx].fingerprints[i] == 0) {
                buckets_[current_idx].fingerprints[i] = fp;
                count_++;
                return true;
            }
        }
    }

    return false; // Filter is full
}

bool CuckooFilter::add(const std::string& str) {
    return add(std::span<const uint8_t>(reinterpret_cast<const uint8_t*>(str.data()), str.size()));
}

bool CuckooFilter::contains(std::span<const uint8_t> data) const {
    uint16_t fp = get_fingerprint(data);
    size_t i1 = hash_index(data);
    size_t i2 = alt_index(i1, fp);

    for (size_t i = 0; i < Bucket::BUCKET_SIZE; ++i) {
        if (buckets_[i1].fingerprints[i] == fp) return true;
        if (buckets_[i2].fingerprints[i] == fp) return true;
    }
    return false;
}

bool CuckooFilter::contains(const std::string& str) const {
    return contains(std::span<const uint8_t>(reinterpret_cast<const uint8_t*>(str.data()), str.size()));
}

bool CuckooFilter::remove(std::span<const uint8_t> data) {
    uint16_t fp = get_fingerprint(data);
    size_t i1 = hash_index(data);
    size_t i2 = alt_index(i1, fp);

    for (size_t i = 0; i < Bucket::BUCKET_SIZE; ++i) {
        if (buckets_[i1].fingerprints[i] == fp) {
            buckets_[i1].fingerprints[i] = 0;
            count_--;
            return true;
        }
        if (buckets_[i2].fingerprints[i] == fp) {
            buckets_[i2].fingerprints[i] = 0;
            count_--;
            return true;
        }
    }
    return false;
}

bool CuckooFilter::remove(const std::string& str) {
    return remove(std::span<const uint8_t>(reinterpret_cast<const uint8_t*>(str.data()), str.size()));
}

} // namespace nit::osnova::ds
