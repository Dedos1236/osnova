#pragma once

#include <cstdint>
#include <span>
#include <vector>

namespace nit::crypto::osnova {

/**
 * @brief SPONGENT lightweight hash function.
 * Core for highly constrained environments (e.g. specialized IoT modules running OSNOVA).
 */
class Spongent {
public:
    enum class HashSize {
        HASH_088 = 88,
        HASH_128 = 128,
        HASH_160 = 160,
        HASH_224 = 224,
        HASH_256 = 256
    };

    explicit Spongent(HashSize size = HashSize::HASH_256) noexcept;

    void update(std::span<const uint8_t> data) noexcept;
    void finalize(std::span<uint8_t> out) noexcept;

private:
    HashSize hash_size_;
    uint16_t rate_;
    uint16_t capacity_;
    uint16_t n_rounds_;
    
    std::vector<uint8_t> state_; // internal state
    std::vector<uint8_t> buffer_; // absorbs input until rate
    
    void permute() noexcept;
};

} // namespace nit::crypto::osnova
