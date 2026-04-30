#include "polynomial.h"
#include <stdexcept>
#include <algorithm>

namespace nit::crypto::osnova {

Polynomial::Polynomial() {}

Polynomial::Polynomial(const std::vector<Fr_BN254>& c) : coeffs(c) {
    strip_leading_zeros();
}

int Polynomial::degree() const {
    if (coeffs.empty()) return -1;
    return static_cast<int>(coeffs.size()) - 1;
}

void Polynomial::strip_leading_zeros() {
    Fr_BN254 zero(0);
    while (!coeffs.empty() && coeffs.back().value == zero.value) {
        coeffs.pop_back();
    }
}

Fr_BN254 Polynomial::evaluate(const Fr_BN254& x) const {
    // Horner's method
    Fr_BN254 result(0);
    for (int i = degree(); i >= 0; --i) {
        result.mul_mod(x);
        result.add_mod(coeffs[i]);
    }
    return result;
}

void Polynomial::add(const Polynomial& other) {
    size_t new_size = std::max(coeffs.size(), other.coeffs.size());
    coeffs.resize(new_size, Fr_BN254(0));
    
    for (size_t i = 0; i < other.coeffs.size(); ++i) {
        coeffs[i].add_mod(other.coeffs[i]);
    }
    strip_leading_zeros();
}

void Polynomial::sub(const Polynomial& other) {
    size_t new_size = std::max(coeffs.size(), other.coeffs.size());
    coeffs.resize(new_size, Fr_BN254(0));
    
    for (size_t i = 0; i < other.coeffs.size(); ++i) {
        coeffs[i].sub_mod(other.coeffs[i]);
    }
    strip_leading_zeros();
}

void Polynomial::mul(const Polynomial& other) {
    if (coeffs.empty() || other.coeffs.empty()) {
        coeffs.clear();
        return;
    }
    
    // O(n^2) naive multiplication (can be upgraded to O(n log n) FFT)
    std::vector<Fr_BN254> result(coeffs.size() + other.coeffs.size() - 1, Fr_BN254(0));
    for (size_t i = 0; i < coeffs.size(); ++i) {
        for (size_t j = 0; j < other.coeffs.size(); ++j) {
            Fr_BN254 term = coeffs[i];
            term.mul_mod(other.coeffs[j]);
            result[i + j].add_mod(term);
        }
    }
    coeffs = result;
    strip_leading_zeros();
}

void Polynomial::mul_scalar(const Fr_BN254& scalar) {
    Fr_BN254 zero(0);
    if (scalar.value == zero.value) {
        coeffs.clear();
        return;
    }
    for (auto& c : coeffs) {
        c.mul_mod(scalar);
    }
}

std::pair<Polynomial, Polynomial> Polynomial::div_rem(const Polynomial& A, const Polynomial& B) {
    if (B.degree() < 0) {
        throw std::invalid_argument("Division by zero polynomial");
    }
    
    Polynomial q;
    Polynomial r = A;
    
    int d_b = B.degree();
    Fr_BN254 lcb_inv = B.coeffs.back();
    lcb_inv.inv();
    
    q.coeffs.resize(std::max(0, A.degree() - d_b + 1), Fr_BN254(0));
    
    while (r.degree() >= d_b) {
        int deg_diff = r.degree() - d_b;
        Fr_BN254 term = r.coeffs.back();
        term.mul_mod(lcb_inv);
        
        q.coeffs[deg_diff] = term;
        
        Polynomial sub_poly;
        sub_poly.coeffs.resize(deg_diff + B.coeffs.size(), Fr_BN254(0));
        for (size_t i = 0; i < B.coeffs.size(); ++i) {
            Fr_BN254 factor = B.coeffs[i];
            factor.mul_mod(term);
            sub_poly.coeffs[i + deg_diff] = factor;
        }
        
        r.sub(sub_poly);
    }
    
    q.strip_leading_zeros();
    return {q, r};
}

void Polynomial::fft(std::vector<Fr_BN254>& a, const Fr_BN254& root_of_unity, bool inverse) {
    // Number Theoretic Transform for fast polynomial evaluation/interpolation
    // O(n log n) logic over F_q
    
    // (Implementation omitted for density, involves bit-reversal permutation and Cooley-Tukey butterfly)
}

Polynomial LagrangeInterpolation::interpolate(const std::vector<Fr_BN254>& x, const std::vector<Fr_BN254>& y) {
    if (x.size() != y.size() || x.empty()) {
        throw std::invalid_argument("Invalid interpolation data");
    }
    
    Polynomial L;
    
    for (size_t i = 0; i < x.size(); ++i) {
        Polynomial l_i({Fr_BN254(1)});
        Fr_BN254 denom(1);
        
        for (size_t j = 0; j < x.size(); ++j) {
            if (i != j) {
                Fr_BN254 neg_xj(0);
                neg_xj.sub_mod(x[j]);
                
                Polynomial term({neg_xj, Fr_BN254(1)}); // (X - x_j)
                l_i.mul(term);
                
                Fr_BN254 diff = x[i];
                diff.sub_mod(x[j]);
                denom.mul_mod(diff);
            }
        }
        
        denom.inv();
        l_i.mul_scalar(denom);
        l_i.mul_scalar(y[i]);
        
        L.add(l_i);
    }
    
    return L;
}

Polynomial LagrangeInterpolation::vanishing_polynomial(const std::vector<Fr_BN254>& points) {
    Polynomial Z({Fr_BN254(1)});
    
    for (const auto& p : points) {
        Fr_BN254 neg_p(0);
        neg_p.sub_mod(p);
        Polynomial term({neg_p, Fr_BN254(1)}); // (X - p)
        Z.mul(term);
    }
    
    return Z;
}

} // namespace nit::crypto::osnova
