#pragma once

#include <cstdint>
#include <vector>
#include <span>
#include <string>

namespace nit::crypto::osnova {

/**
 * @brief Multi-precision integer arithmetic (Bignum).
 * Primarily used for RSA, DH, and ECC implementations that 
 * cannot rely on fixed-width architectures. Provides 
 * constant-time operations where applicable.
 */
class BigNum {
public:
    BigNum() noexcept = default;
    explicit BigNum(uint64_t val) noexcept;
    BigNum(std::span<const uint8_t> bytes, bool big_endian = true) noexcept;
    explicit BigNum(std::string_view hex) noexcept;
    BigNum(const BigNum& other) = default;
    BigNum(BigNum&& other) noexcept = default;

    BigNum& operator=(const BigNum& other) = default;
    BigNum& operator=(BigNum&& other) noexcept = default;

    static BigNum from_hex(std::string_view hex) noexcept {
        return BigNum(hex);
    }

    // Basic arithmetic
    void add(const BigNum& a, const BigNum& b) noexcept;
    void sub(const BigNum& a, const BigNum& b) noexcept;
    void mul(const BigNum& a, const BigNum& b) noexcept;
    void div(const BigNum& a, const BigNum& b, BigNum& q, BigNum& r) const noexcept;

    BigNum add(const BigNum& other) const noexcept { BigNum r; r.add(*this, other); return r; }
    BigNum sub(const BigNum& other) const noexcept { BigNum r; r.sub(*this, other); return r; }
    BigNum mul(const BigNum& other) const noexcept { BigNum r; r.mul(*this, other); return r; }
    BigNum mod(const BigNum& m) const noexcept { BigNum q, r; div(*this, m, q, r); return r; }

    // Modular arithmetic
    void mod_add(const BigNum& a, const BigNum& b, const BigNum& m) noexcept;
    void mod_sub(const BigNum& a, const BigNum& b, const BigNum& m) noexcept;
    void mod_mul(const BigNum& a, const BigNum& b, const BigNum& m) noexcept;
    void mod_exp(const BigNum& base, const BigNum& exp, const BigNum& m) noexcept;
    void mod_inv(const BigNum& a, const BigNum& m) noexcept;

    BigNum mod_add(const BigNum& other, const BigNum& m) const noexcept { BigNum r; r.mod_add(*this, other, m); return r; }
    BigNum mod_sub(const BigNum& other, const BigNum& m) const noexcept { BigNum r; r.mod_sub(*this, other, m); return r; }
    BigNum mod_mul(const BigNum& other, const BigNum& m) const noexcept { BigNum r; r.mod_mul(*this, other, m); return r; }
    BigNum mod_pow(const BigNum& exp, const BigNum& m) const noexcept { BigNum r; r.mod_exp(*this, exp, m); return r; }
    BigNum mod_inv(const BigNum& m) const noexcept { BigNum r; r.mod_inv(*this, m); return r; }

    // Comparisons
    int cmp(const BigNum& other) const noexcept;
    bool is_zero() const noexcept;
    bool is_even() const noexcept;

    // Utilities
    void shift_left(uint32_t bits) noexcept;
    void shift_right(uint32_t bits) noexcept;
    void set_bit(uint32_t bit) noexcept;
    int bit_length() const noexcept;
    
    std::vector<uint8_t> to_bytes_be() const noexcept;
    std::vector<uint8_t> to_bytes() const noexcept { return to_bytes_be(); }
    std::vector<uint8_t> to_bytes_padded(size_t length) const noexcept;
    std::string to_hex() const noexcept;

private:
    std::vector<uint32_t> limbs_; // Base 2^32 representation
    int sign_ = 1; // 1 for positive, -1 for negative

    void strip_leading_zeros() noexcept;
    static int cmp_abs(const BigNum& a, const BigNum& b) noexcept;
    void add_abs(const BigNum& a, const BigNum& b) noexcept;
    void sub_abs(const BigNum& a, const BigNum& b) noexcept;
};

} // namespace nit::crypto::osnova
