#pragma once

#include <cstdint>
#include <span>
#include <mutex>
#include "hmac_drbg.h"

namespace nit::crypto::osnova {

/**
 * @brief Thread-safe Secure Random Number Generator.
 * Combines OS entropy source with HMAC-DRBG.
 */
class SecureRandom {
public:
    static SecureRandom& get_instance() noexcept;

    SecureRandom(const SecureRandom&) = delete;
    SecureRandom& operator=(const SecureRandom&) = delete;

    /**
     * @brief Generate random bytes.
     */
    void generate(std::span<uint8_t> out) noexcept;

    /**
     * @brief Formally reseed the internal DRBG from OS.
     */
    void reseed() noexcept;

private:
    SecureRandom() noexcept;

    /**
     * @brief Get true OS entropy.
     */
    void get_os_entropy(std::span<uint8_t> out) noexcept;

    std::mutex mtx_;
    HmacDrbg drbg_;
    bool initialized_;
};

} // namespace nit::crypto::osnova
