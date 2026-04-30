#pragma once

#include <cstdint>
#include <vector>
#include <span>

namespace nit::crypto::osnova {

/**
 * @brief GOST R 34.11-2012 (Streebog) Hash Function.
 * Certified cryptographic hash function compliant with the Russian Federation standard.
 * Crucial for local regulatory compliance and integration into enterprise C2S environments.
 * Outputs either 256 bits or 512 bits.
 */
class GostStreebog {
public:
    enum class DigestSize {
        HASH_256 = 32,
        HASH_512 = 64
    };

    /**
     * @brief Computes the Streebog hash of the input data.
     * @param out Output buffer to store the hash. Must be sized according to digest_size.
     * @param data Input data span.
     * @param digest_size DigestSize::HASH_256 or DigestSize::HASH_512.
     */
    static void compute(
        std::span<uint8_t> out,
        std::span<const uint8_t> data,
        DigestSize digest_size);

    class Context {
    public:
        explicit Context(DigestSize digest_size);
        void update(std::span<const uint8_t> data);
        void finalize(std::span<uint8_t> out);

    private:
        DigestSize digest_size_;
        uint8_t buffer_[64];
        size_t buffer_len_;
        uint64_t total_len_;
        std::vector<uint8_t> h_; // Internal state
        std::vector<uint8_t> N_; // Counter
        std::vector<uint8_t> Sigma_; // Sum

        void g(std::span<const uint8_t> N, std::span<const uint8_t> m);
        void add_mod512(std::vector<uint8_t>& a, const std::vector<uint8_t>& b);
    };
};

} // namespace nit::crypto::osnova
