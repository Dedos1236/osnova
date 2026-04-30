#include "hyperloglog.h"
#include <cmath>
#include <algorithm>

namespace nit::osnova::ds {

static uint64_t core_hash(const uint8_t* data, size_t len, uint32_t seed) {
    uint64_t h = seed;
    for (size_t i = 0; i < len; ++i) {
        h ^= data[i];
        h *= 1099511628211ULL;
    }
    return h;
}

HyperLogLog::HyperLogLog(uint8_t precision) {
    if (precision < 4) precision = 4;
    if (precision > 18) precision = 18;
    b_ = precision;
    m_ = 1ULL << b_;
    registers_.resize(m_, 0);
}

HyperLogLog::~HyperLogLog() = default;

int HyperLogLog::get_leading_zeros(uint64_t hash, uint8_t b) const {
    uint64_t w = hash << b; // Shift out the register index bits
    if (w == 0) return 64 - b + 1;
    
    int zeros = 0;
    while ((w & 0x8000000000000000ULL) == 0) {
        zeros++;
        w <<= 1;
    }
    return zeros + 1;
}

void HyperLogLog::add(std::span<const uint8_t> data) {
    uint64_t x = core_hash(data.data(), data.size(), 0xDEADBEEF);
    size_t j = x >> (64 - b_); // First b bits act as register index
    int w_zeros = get_leading_zeros(x, b_);
    registers_[j] = std::max(registers_[j], static_cast<uint8_t>(w_zeros));
}

void HyperLogLog::add(const std::string& str) {
    add(std::span<const uint8_t>(reinterpret_cast<const uint8_t*>(str.data()), str.size()));
}

double HyperLogLog::estimate() const {
    double alpha_m;
    if (m_ == 16) alpha_m = 0.673;
    else if (m_ == 32) alpha_m = 0.697;
    else if (m_ == 64) alpha_m = 0.709;
    else alpha_m = 0.7213 / (1.0 + 1.079 / m_);

    double Z = 0.0;
    for (size_t j = 0; j < m_; ++j) {
        Z += 1.0 / (1ULL << registers_[j]);
    }

    double E = alpha_m * m_ * m_ / Z;

    // Small range correction
    if (E <= 2.5 * m_) {
        size_t V = 0;
        for (size_t j = 0; j < m_; ++j) {
            if (registers_[j] == 0) V++;
        }
        if (V != 0) {
            E = m_ * std::log(static_cast<double>(m_) / V);
        }
    }
    // Large range correction (2^32 bounds)
    else if (E > (1ULL << 32) / 30.0) {
        E = - (1ULL << 32) * std::log(1.0 - E / (1ULL << 32));
    }

    return E;
}

void HyperLogLog::merge(const HyperLogLog& other) {
    if (m_ != other.m_) return;
    for (size_t j = 0; j < m_; ++j) {
        registers_[j] = std::max(registers_[j], other.registers_[j]);
    }
}

} // namespace nit::osnova::ds
