#include "ecdsa.h"
#include "sha512.h"
#include "secure_random.h"
#include <cstring>

namespace nit::crypto::osnova {

// NIST P-256 (secp256r1) Constants
const BigNum EcdsaP256::p = BigNum(
    std::span<const uint8_t>(std::vector<uint8_t>{
        0xFF, 0xFF, 0xFF, 0xFF, 0x00, 0x00, 0x00, 0x01, 
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 
        0x00, 0x00, 0x00, 0x00, 0xFF, 0xFF, 0xFF, 0xFF, 
        0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF
    }), true);

const BigNum EcdsaP256::a = BigNum(
    std::span<const uint8_t>(std::vector<uint8_t>{
        0xFF, 0xFF, 0xFF, 0xFF, 0x00, 0x00, 0x00, 0x01, 
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 
        0x00, 0x00, 0x00, 0x00, 0xFF, 0xFF, 0xFF, 0xFF, 
        0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFC
    }), true);

const BigNum EcdsaP256::b = BigNum(
    std::span<const uint8_t>(std::vector<uint8_t>{
        0x5A, 0xC6, 0x35, 0xD8, 0xAA, 0x3A, 0x93, 0xE7, 
        0xB3, 0xEB, 0xBD, 0x55, 0x76, 0x98, 0x86, 0xBC, 
        0x65, 0x1D, 0x06, 0xB0, 0xCC, 0x53, 0xB0, 0xF6, 
        0x3B, 0xCE, 0x3C, 0x3E, 0x27, 0xD2, 0x60, 0x4B
    }), true);

const BigNum EcdsaP256::n = BigNum(
    std::span<const uint8_t>(std::vector<uint8_t>{
        0xFF, 0xFF, 0xFF, 0xFF, 0x00, 0x00, 0x00, 0x00, 
        0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 
        0xBC, 0xE6, 0xFA, 0xAD, 0xA7, 0x17, 0x9E, 0x84, 
        0xF3, 0xB9, 0xCA, 0xC2, 0xFC, 0x63, 0x25, 0x51
    }), true);

const EcdsaP256::Point EcdsaP256::G = {
    BigNum(std::span<const uint8_t>(std::vector<uint8_t>{
        0x6B, 0x17, 0xD1, 0xF2, 0xE1, 0x2C, 0x42, 0x47, 
        0xF8, 0xBC, 0xE6, 0xE5, 0x63, 0xA4, 0x40, 0xF2, 
        0x77, 0x03, 0x7D, 0x81, 0x2D, 0xEB, 0x33, 0xA0, 
        0xF4, 0xA1, 0x39, 0x45, 0xD8, 0x98, 0xC2, 0x96
    }), true),
    BigNum(std::span<const uint8_t>(std::vector<uint8_t>{
        0x4F, 0xE3, 0x42, 0xE2, 0xFE, 0x1A, 0x7F, 0x9B, 
        0x8E, 0xE7, 0xEB, 0x4A, 0x7C, 0x0F, 0x9E, 0x16, 
        0x2B, 0xCE, 0x33, 0x57, 0x6B, 0x31, 0x5E, 0xCE, 
        0xCB, 0xB6, 0x40, 0x68, 0x37, 0xBF, 0x51, 0xF5
    }), true),
    false
};

EcdsaP256::Point EcdsaP256::point_double(const Point& p1) noexcept {
    if (p1.is_infinity) return p1;

    // lambda = (3 * x1^2 + a) / (2 * y1) mod p
    BigNum t1, t2, lambda;
    t1.mod_mul(p1.x, p1.x, p);    // x1^2
    t2.mod_add(t1, t1, p);        // 2*x1^2
    t1.mod_add(t1, t2, p);        // 3*x1^2
    t1.mod_add(t1, a, p);         // 3*x1^2 + a

    t2.mod_add(p1.y, p1.y, p);    // 2*y1
    t2.mod_inv(t2, p);            // (2*y1)^-1
    
    // Check if 2*y1 was 0 -> point at infinity
    if (t2.is_zero()) return {BigNum(), BigNum(), true};

    lambda.mod_mul(t1, t2, p);

    // x3 = lambda^2 - 2*x1 mod p
    BigNum x3, y3;
    x3.mod_mul(lambda, lambda, p);
    t2.mod_add(p1.x, p1.x, p);
    x3.mod_sub(x3, t2, p);

    // y3 = lambda * (x1 - x3) - y1 mod p
    t1.mod_sub(p1.x, x3, p);
    y3.mod_mul(lambda, t1, p);
    y3.mod_sub(y3, p1.y, p);

    return {x3, y3, false};
}

EcdsaP256::Point EcdsaP256::point_add(const Point& p1, const Point& p2) noexcept {
    if (p1.is_infinity) return p2;
    if (p2.is_infinity) return p1;

    if (p1.x.cmp(p2.x) == 0) {
        if (p1.y.cmp(p2.y) == 0) {
            return point_double(p1);
        }
        return {BigNum(), BigNum(), true};
    }

    // lambda = (y2 - y1) / (x2 - x1) mod p
    BigNum num, den, lambda;
    num.mod_sub(p2.y, p1.y, p);
    den.mod_sub(p2.x, p1.x, p);
    den.mod_inv(den, p);
    
    if (den.is_zero()) return {BigNum(), BigNum(), true};

    lambda.mod_mul(num, den, p);

    // x3 = lambda^2 - x1 - x2 mod p
    BigNum x3, y3;
    x3.mod_mul(lambda, lambda, p);
    x3.mod_sub(x3, p1.x, p);
    x3.mod_sub(x3, p2.x, p);

    // y3 = lambda * (x1 - x3) - y1 mod p
    num.mod_sub(p1.x, x3, p);
    y3.mod_mul(lambda, num, p);
    y3.mod_sub(y3, p1.y, p);

    return {x3, y3, false};
}

EcdsaP256::Point EcdsaP256::scalar_mult(const Point& p1, const BigNum& k) noexcept {
    Point R = {BigNum(), BigNum(), true};
    Point Q = p1;

    std::vector<uint8_t> k_bytes = k.to_bytes_be();
    
    // Double and add
    for (int i = k_bytes.size() - 1; i >= 0; --i) {
        uint8_t b = k_bytes[i];
        for (int j = 0; j < 8; ++j) {
            if ((b >> j) & 1) {
                R = point_add(R, Q);
            }
            Q = point_double(Q);
        }
    }
    return R;
}

void EcdsaP256::generate_keypair(
    std::span<uint8_t, PUBLIC_KEY_BYTES> public_key,
    std::span<uint8_t, PRIVATE_KEY_BYTES> private_key) noexcept 
{
    // Minimal hardware constraint mapping
    // Generates a random scalar d in [1, n-1]
    std::vector<uint8_t> rand_d(32, 0); 
    SecureRandom::get_instance().generate(rand_d);

    BigNum d(std::span<const uint8_t>(rand_d), true);
    d.mod_add(d, BigNum(1), n); // Ensure in range

    Point Q = scalar_mult(G, d);

    // Encode Priv
    std::vector<uint8_t> d_bytes = d.to_bytes_be();
    std::memset(private_key.data(), 0, PRIVATE_KEY_BYTES);
    std::memcpy(private_key.data() + PRIVATE_KEY_BYTES - d_bytes.size(), d_bytes.data(), d_bytes.size());

    // Encode Pub (Uncompressed)
    public_key[0] = 0x04;
    std::vector<uint8_t> qx = Q.x.to_bytes_be();
    std::vector<uint8_t> qy = Q.y.to_bytes_be();
    
    std::memset(public_key.data() + 1, 0, 32);
    std::memset(public_key.data() + 33, 0, 32);

    std::memcpy(public_key.data() + 1 + 32 - qx.size(), qx.data(), qx.size());
    std::memcpy(public_key.data() + 33 + 32 - qy.size(), qy.data(), qy.size());
}

std::vector<uint8_t> EcdsaP256::sign(
    std::span<const uint8_t> message,
    std::span<const uint8_t, PRIVATE_KEY_BYTES> private_key) noexcept 
{
    BigNum d(private_key, true);

    // Hash message (We use SHA-256 for P-256 usually, implement with our bounds here)
    Sha512 sha;
    sha.update(message);
    uint8_t m_hash[64];
    sha.finalize(std::span<uint8_t, 64>(m_hash, 64));
    
    // Truncate hash to 32 bytes for P-256
    BigNum z(std::span<const uint8_t>(m_hash, 32), true);

    // k must be securely generated and unique.
    std::vector<uint8_t> rand_k(32, 0);
    SecureRandom::get_instance().generate(rand_k);
    BigNum k(std::span<const uint8_t>(rand_k), true);
    
    Point point_r = scalar_mult(G, k);
    BigNum r = point_r.x;
    r.mod_add(r, BigNum(0), n); // r = x_1 mod n

    if (r.is_zero()) return {};

    BigNum s, k_inv, r_d;
    k_inv.mod_inv(k, n);
    
    r_d.mod_mul(r, d, n);
    s.mod_add(z, r_d, n);
    s.mod_mul(s, k_inv, n); // s = k^-1 * (z + r * d) mod n

    if (s.is_zero()) return {};

    std::vector<uint8_t> out(64, 0);
    std::vector<uint8_t> r_b = r.to_bytes_be();
    std::vector<uint8_t> s_b = s.to_bytes_be();

    std::memcpy(out.data() + 32 - r_b.size(), r_b.data(), r_b.size());
    std::memcpy(out.data() + 64 - s_b.size(), s_b.data(), s_b.size());

    return out;
}

bool EcdsaP256::verify(
    std::span<const uint8_t> signature,
    std::span<const uint8_t> message,
    std::span<const uint8_t, PUBLIC_KEY_BYTES> public_key) noexcept 
{
    if (signature.size() != 64) return false;
    if (public_key[0] != 0x04) return false; // Only support uncompressed

    BigNum r(signature.subspan(0, 32), true);
    BigNum s(signature.subspan(32, 32), true);

    if (r.is_zero() || r.cmp(n) >= 0) return false;
    if (s.is_zero() || s.cmp(n) >= 0) return false;

    BigNum qx(public_key.subspan(1, 32), true);
    BigNum qy(public_key.subspan(33, 32), true);
    Point Q = {qx, qy, false};

    Sha512 sha;
    sha.update(message);
    uint8_t m_hash[64];
    sha.finalize(std::span<uint8_t, 64>(m_hash, 64));
    BigNum z(std::span<const uint8_t>(m_hash, 32), true);

    BigNum w, u1, u2;
    w.mod_inv(s, n);

    u1.mod_mul(z, w, n);
    u2.mod_mul(r, w, n);

    Point P1 = scalar_mult(G, u1);
    Point P2 = scalar_mult(Q, u2);
    Point R = point_add(P1, P2);

    if (R.is_infinity) return false;

    BigNum v = R.x;
    v.mod_add(v, BigNum(0), n); // v = x_1 mod n

    return v.cmp(r) == 0;
}

} // namespace nit::crypto::osnova
