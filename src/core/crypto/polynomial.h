#pragma once
#include <vector>
#include "ff_bn254.h"

namespace nit::crypto::osnova {

// Dense polynomial representation over Fr_BN254
// P(X) = c_0 + c_1 * X + c_2 * X^2 + ... + c_n * X^n
class Polynomial {
public:
    std::vector<Fr_BN254> coeffs;

    Polynomial();
    explicit Polynomial(const std::vector<Fr_BN254>& c);
    
    // Degree of the polynomial (index of highest non-zero coefficient)
    int degree() const;
    
    // Strip trailing zero coefficients
    void strip_leading_zeros();

    // Evaluate polynomial at point x
    Fr_BN254 evaluate(const Fr_BN254& x) const;

    // Polynomial arithmetic
    void add(const Polynomial& other);
    void sub(const Polynomial& other);
    void mul(const Polynomial& other);
    
    // Scalar operations
    void mul_scalar(const Fr_BN254& scalar);

    // Division with remainder: A(X) = Q(X)*B(X) + R(X)
    // Returns {Q(X), R(X)}
    static std::pair<Polynomial, Polynomial> div_rem(const Polynomial& A, const Polynomial& B);
    
    // Fast Fourier Transform over prime field for fast polynomial multiplication
    // Evaluates the polynomial on the roots of unity
    static void fft(std::vector<Fr_BN254>& a, const Fr_BN254& root_of_unity, bool inverse);
};

// Lagrange Interpolation utilities for PLONK
class LagrangeInterpolation {
public:
    // Generate polynomial from a set of evaluated points
    static Polynomial interpolate(const std::vector<Fr_BN254>& x, const std::vector<Fr_BN254>& y);
    
    // Compute vanishing polynomial: Z(X) = (X - x_0)(X - x_1)...(X - x_n)
    static Polynomial vanishing_polynomial(const std::vector<Fr_BN254>& points);
};

} // namespace nit::crypto::osnova
