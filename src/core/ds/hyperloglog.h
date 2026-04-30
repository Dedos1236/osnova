#pragma once

#include <vector>
#include <cstdint>
#include <string>
#include <span>

namespace nit::osnova::ds {

/**
 * @brief HyperLogLog implementation.
 * Probabilistic data structure for estimating the cardinality of a massive multiset 
 * (number of distinct elements) using very little memory.
 * Used in OSNOVA to estimate daily active peers in the unstructured mesh without 
 * tracking exact identities.
 */
class HyperLogLog {
public:
    explicit HyperLogLog(uint8_t precision = 14); // 14 gives ~16k registers, ~1% standard error
    ~HyperLogLog();

    void add(std::span<const uint8_t> data);
    void add(const std::string& str);

    /**
     * @brief Estimate the number of unique elements inserted.
     */
    double estimate() const;

    /**
     * @brief Merge another HyperLogLog to estimate union cardinality.
     */
    void merge(const HyperLogLog& other);

private:
    uint8_t b_; // Precision bits
    size_t m_;  // Number of registers (2^b)
    std::vector<uint8_t> registers_;

    int get_leading_zeros(uint64_t hash, uint8_t b) const;
};

} // namespace nit::osnova::ds
