#include "bignum.h"
#include <iomanip>
#include <sstream>
#include <algorithm>
#include <stdexcept>

namespace nit::crypto::osnova {

BigNum::BigNum(uint64_t val) noexcept {
    if (val == 0) {
        limbs_.push_back(0);
    } else {
        limbs_.push_back(val & 0xFFFFFFFF);
        if (val >> 32) {
            limbs_.push_back(val >> 32);
        }
    }
}

BigNum::BigNum(std::span<const uint8_t> bytes, bool big_endian) noexcept {
    if (bytes.empty()) {
        limbs_.push_back(0);
        return;
    }

    size_t size = bytes.size();
    limbs_.resize((size + 3) / 4, 0);

    for (size_t i = 0; i < size; ++i) {
        size_t b_idx = big_endian ? (size - 1 - i) : i;
        limbs_[i / 4] |= (static_cast<uint32_t>(bytes[b_idx]) << ((i % 4) * 8));
    }
    strip_leading_zeros();
}

BigNum::BigNum(std::string_view hex) noexcept {
    if (hex.empty()) {
        limbs_.push_back(0);
        return;
    }
    
    // Quick hex to bytes
    std::string hex_str(hex);
    if (hex_str.substr(0, 2) == "0x" || hex_str.substr(0, 2) == "0X") {
        hex_str = hex_str.substr(2);
    }
    
    if (hex_str.length() % 2 != 0) {
        hex_str = "0" + hex_str;
    }
    
    std::vector<uint8_t> bytes;
    bytes.reserve(hex_str.length() / 2);
    for (size_t i = 0; i < hex_str.length(); i += 2) {
        std::string byteString = hex_str.substr(i, 2);
        uint8_t byte = (uint8_t)strtol(byteString.c_str(), nullptr, 16);
        bytes.push_back(byte);
    }
    
    *this = BigNum(bytes, true);
}

void BigNum::strip_leading_zeros() noexcept {
    while (limbs_.size() > 1 && limbs_.back() == 0) {
        limbs_.pop_back();
    }
    if (limbs_.size() == 1 && limbs_[0] == 0) {
        sign_ = 1;
    }
}

bool BigNum::is_zero() const noexcept {
    return limbs_.size() == 1 && limbs_[0] == 0;
}

bool BigNum::is_even() const noexcept {
    if (limbs_.empty()) return true;
    return (limbs_[0] & 1) == 0;
}

int BigNum::cmp_abs(const BigNum& a, const BigNum& b) noexcept {
    if (a.limbs_.size() != b.limbs_.size()) {
        return a.limbs_.size() < b.limbs_.size() ? -1 : 1;
    }
    for (int i = static_cast<int>(a.limbs_.size()) - 1; i >= 0; --i) {
        if (a.limbs_[i] != b.limbs_[i]) {
            return a.limbs_[i] < b.limbs_[i] ? -1 : 1;
        }
    }
    return 0;
}

int BigNum::cmp(const BigNum& other) const noexcept {
    if (sign_ != other.sign_) {
        return sign_ < other.sign_ ? -1 : 1;
    }
    int c = cmp_abs(*this, other);
    return sign_ == 1 ? c : -c;
}

void BigNum::add_abs(const BigNum& a, const BigNum& b) noexcept {
    size_t max_size = std::max(a.limbs_.size(), b.limbs_.size());
    limbs_.resize(max_size, 0);

    uint64_t carry = 0;
    for (size_t i = 0; i < max_size; ++i) {
        uint64_t val = carry;
        if (i < a.limbs_.size()) val += a.limbs_[i];
        if (i < b.limbs_.size()) val += b.limbs_[i];
        limbs_[i] = val & 0xFFFFFFFF;
        carry = val >> 32;
    }
    if (carry) {
        limbs_.push_back(carry);
    }
    strip_leading_zeros();
}

void BigNum::sub_abs(const BigNum& a, const BigNum& b) noexcept {
    // Requires a >= b
    limbs_.resize(a.limbs_.size(), 0);

    int64_t borrow = 0;
    for (size_t i = 0; i < a.limbs_.size(); ++i) {
        int64_t val = a.limbs_[i] - borrow;
        if (i < b.limbs_.size()) val -= b.limbs_[i];

        if (val < 0) {
            val += 0x100000000LL;
            borrow = 1;
        } else {
            borrow = 0;
        }
        limbs_[i] = static_cast<uint32_t>(val);
    }
    strip_leading_zeros();
}

void BigNum::add(const BigNum& a, const BigNum& b) noexcept {
    if (a.sign_ == b.sign_) {
        add_abs(a, b);
        sign_ = a.sign_;
    } else {
        if (cmp_abs(a, b) >= 0) {
            sub_abs(a, b);
            sign_ = a.sign_;
        } else {
            sub_abs(b, a);
            sign_ = b.sign_;
        }
    }
}

void BigNum::sub(const BigNum& a, const BigNum& b) noexcept {
    if (a.sign_ != b.sign_) {
        add_abs(a, b);
        sign_ = a.sign_;
    } else {
        if (cmp_abs(a, b) >= 0) {
            sub_abs(a, b);
            sign_ = a.sign_;
        } else {
            sub_abs(b, a);
            sign_ = -a.sign_;
        }
    }
}

void BigNum::mul(const BigNum& a, const BigNum& b) noexcept {
    if (a.is_zero() || b.is_zero()) {
        limbs_ = {0};
        sign_ = 1;
        return;
    }

    std::vector<uint32_t> res(a.limbs_.size() + b.limbs_.size(), 0);

    for (size_t i = 0; i < a.limbs_.size(); ++i) {
        uint64_t carry = 0;
        for (size_t j = 0; j < b.limbs_.size(); ++j) {
            uint64_t val = static_cast<uint64_t>(a.limbs_[i]) * b.limbs_[j] + res[i + j] + carry;
            res[i + j] = val & 0xFFFFFFFF;
            carry = val >> 32;
        }
        res[i + b.limbs_.size()] = carry;
    }

    limbs_ = std::move(res);
    sign_ = (a.sign_ == b.sign_) ? 1 : -1;
    strip_leading_zeros();
}

int BigNum::bit_length() const noexcept {
    if (is_zero()) return 0;
    int bits = (limbs_.size() - 1) * 32;
    uint32_t top = limbs_.back();
    while (top) {
        bits++;
        top >>= 1;
    }
    return bits;
}

void BigNum::shift_left(uint32_t bits) noexcept {
    if (is_zero() || bits == 0) return;

    size_t words = bits / 32;
    uint32_t shift = bits % 32;

    if (words > 0) {
        limbs_.insert(limbs_.begin(), words, 0);
    }

    if (shift > 0) {
        uint32_t carry = 0;
        for (size_t i = words; i < limbs_.size(); ++i) {
            uint32_t next_carry = limbs_[i] >> (32 - shift);
            limbs_[i] = (limbs_[i] << shift) | carry;
            carry = next_carry;
        }
        if (carry) {
            limbs_.push_back(carry);
        }
    }
}

void BigNum::shift_right(uint32_t bits) noexcept {
    if (is_zero() || bits == 0) return;

    size_t words = bits / 32;
    uint32_t shift = bits % 32;

    if (words >= limbs_.size()) {
        limbs_ = {0};
        return;
    }

    if (words > 0) {
        limbs_.erase(limbs_.begin(), limbs_.begin() + words);
    }

    if (shift > 0) {
        uint32_t carry = 0;
        for (int i = static_cast<int>(limbs_.size()) - 1; i >= 0; --i) {
            uint32_t next_carry = limbs_[i] << (32 - shift);
            limbs_[i] = (limbs_[i] >> shift) | carry;
            carry = next_carry;
        }
    }
    strip_leading_zeros();
}

void BigNum::div(const BigNum& a, const BigNum& b, BigNum& q, BigNum& r) const noexcept {
    if (b.is_zero()) {
        // Divide by zero. Handling omitted for simplicity.
        return;
    }

    if (cmp_abs(a, b) < 0) {
        q = BigNum(0);
        r = a;
        return;
    }

    q = BigNum(0);
    r = a;
    r.sign_ = 1; // Work with absolutes

    BigNum d = b;
    d.sign_ = 1;

    int shift = a.bit_length() - b.bit_length();
    d.shift_left(shift);

    for (int i = 0; i <= shift; ++i) {
        q.shift_left(1);
        if (cmp_abs(r, d) >= 0) {
            r.sub_abs(r, d);
            q.limbs_[0] |= 1;
        }
        d.shift_right(1);
    }

    q.sign_ = (a.sign_ == b.sign_) ? 1 : -1;
    r.sign_ = a.sign_;
}

void BigNum::mod_add(const BigNum& a, const BigNum& b, const BigNum& m) noexcept {
    add(a, b);
    BigNum q, r;
    div(*this, m, q, r);
    *this = r;
    if (sign_ < 0) add(*this, m);
}

void BigNum::mod_sub(const BigNum& a, const BigNum& b, const BigNum& m) noexcept {
    sub(a, b);
    BigNum q, r;
    div(*this, m, q, r);
    *this = r;
    if (sign_ < 0) add(*this, m);
}

void BigNum::mod_mul(const BigNum& a, const BigNum& b, const BigNum& m) noexcept {
    mul(a, b);
    BigNum q, r;
    div(*this, m, q, r);
    *this = r;
    if (sign_ < 0) add(*this, m);
}

void BigNum::mod_exp(const BigNum& base, const BigNum& exp, const BigNum& m) noexcept {
    BigNum res(1);
    BigNum b = base;
    
    BigNum q, r;
    b.div(b, m, q, r);
    b = r;

    for (size_t i = 0; i < exp.limbs_.size(); ++i) {
        for (int j = 0; j < 32; ++j) {
            if ((exp.limbs_[i] >> j) & 1) {
                res.mod_mul(res, b, m);
            }
            b.mod_mul(b, b, m);
        }
    }
    *this = res;
}

void BigNum::mod_inv(const BigNum& a, const BigNum& m) noexcept {
    // Extended Euclidean Algorithm
    BigNum t(0), newt(1);
    BigNum r = m, newr = a;

    while (!newr.is_zero()) {
        BigNum q, rem;
        div(r, newr, q, rem);

        BigNum tmp_t;
        tmp_t.mul(q, newt);
        tmp_t.sub(t, tmp_t);
        t = newt;
        newt = tmp_t;

        r = newr;
        newr = rem;
    }

    if (r.cmp(BigNum(1)) > 0) {
        // Not invertible
        *this = BigNum(0);
        return;
    }

    if (t.sign_ < 0) {
        t.add(t, m);
    }
    *this = t;
}

std::vector<uint8_t> BigNum::to_bytes_be() const noexcept {
    if (is_zero()) return {0};
    
    std::vector<uint8_t> res;
    for (int i = static_cast<int>(limbs_.size()) - 1; i >= 0; --i) {
        uint32_t val = limbs_[i];
        if (i == static_cast<int>(limbs_.size()) - 1) {
            if (val >> 24) res.push_back(val >> 24);
            if (val >> 16) res.push_back((val >> 16) & 0xFF);
            if (val >> 8) res.push_back((val >> 8) & 0xFF);
            res.push_back(val & 0xFF);
        } else {
            res.push_back(val >> 24);
            res.push_back((val >> 16) & 0xFF);
            res.push_back((val >> 8) & 0xFF);
            res.push_back(val & 0xFF);
        }
    }
    return res;
}

std::vector<uint8_t> BigNum::to_bytes_padded(size_t length) const noexcept {
    auto bytes = to_bytes_be();
    if (bytes.size() >= length) {
        // If it's larger or equal, just return the truncated or full 
        // (usually we want the rightmost bytes if truncated)
        std::vector<uint8_t> res;
        for(size_t i = bytes.size() - length; i < bytes.size(); ++i) {
            res.push_back(bytes[i]);
        }
        return res;
    }
    std::vector<uint8_t> res(length - bytes.size(), 0);
    res.insert(res.end(), bytes.begin(), bytes.end());
    return res;
}

std::string BigNum::to_hex() const noexcept {
    if (is_zero()) return "0";
    
    std::stringstream ss;
    if (sign_ < 0) ss << "-";
    
    ss << std::hex << std::uppercase;
    for (int i = static_cast<int>(limbs_.size()) - 1; i >= 0; --i) {
        if (i == static_cast<int>(limbs_.size()) - 1) {
            ss << limbs_[i];
        } else {
            ss << std::setfill('0') << std::setw(8) << limbs_[i];
        }
    }
    return ss.str();
}

} // namespace nit::crypto::osnova
