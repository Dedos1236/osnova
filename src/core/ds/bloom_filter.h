#pragma once

#include <vector>
#include <cstdint>
#include <string>
#include <span>

namespace nit::osnova::ds {

/**
 * @brief Bloom Filter implementation.
 * Space-efficient probabilistic data structures that is used to test 
 * whether an element is a member of a set.
 * False positive matches are possible, but false negatives are not.
 */
class BloomFilter {
public:
    /**
     * @brief Initialize Bloom Filter.
     * @param expected_elements Expected number of items to insert.
     * @param false_positive_rate Desired false positive probability (e.g., 0.01 for 1%).
     */
    BloomFilter(size_t expected_elements, double false_positive_rate);
    ~BloomFilter();

    void add(std::span<const uint8_t> data);
    void add(const std::string& str);

    bool possibly_contains(std::span<const uint8_t> data) const;
    bool possibly_contains(const std::string& str) const;

    void clear();

    std::vector<uint8_t> serialize() const;
    static BloomFilter deserialize(const std::vector<uint8_t>& data);

private:
    BloomFilter() = default; // for deserialization

    std::vector<uint64_t> bit_set_;
    size_t num_bits_;
    size_t num_hash_functions_;

    std::vector<uint64_t> hash(std::span<const uint8_t> data) const;
};

} // namespace nit::osnova::ds
