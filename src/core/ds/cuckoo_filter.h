#pragma once

#include <vector>
#include <cstdint>
#include <string>
#include <span>

namespace nit::osnova::ds {

/**
 * @brief Cuckoo Filter implementation.
 * Better than a Bloom filter: supports deletion and is more space-efficient 
 * for low false positive rates.
 */
class CuckooFilter {
public:
    CuckooFilter(size_t max_capacity);
    ~CuckooFilter();

    bool add(std::span<const uint8_t> data);
    bool add(const std::string& str);

    bool contains(std::span<const uint8_t> data) const;
    bool contains(const std::string& str) const;

    bool remove(std::span<const uint8_t> data);
    bool remove(const std::string& str);

private:
    struct Bucket {
        static constexpr size_t BUCKET_SIZE = 4;
        uint16_t fingerprints[BUCKET_SIZE];
        Bucket() {
            for (size_t i=0; i<BUCKET_SIZE; ++i) fingerprints[i] = 0; // 0 is empty
        }
    };

    std::vector<Bucket> buckets_;
    size_t num_buckets_;
    size_t count_ = 0;

    static constexpr size_t MAX_KICKS = 500;

    uint16_t get_fingerprint(std::span<const uint8_t> data) const;
    size_t hash_index(std::span<const uint8_t> data) const;
    size_t alt_index(size_t index, uint16_t fingerprint) const;
};

} // namespace nit::osnova::ds
