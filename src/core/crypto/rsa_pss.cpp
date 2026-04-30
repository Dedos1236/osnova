#include "rsa_pss.h"
#include "sha512.h"
#include "secure_random.h"
#include <cstring>
#include <memory>

namespace nit::crypto::osnova {

namespace {

    // Helper to generate a random BigNum of a specific bit length.
    bool miller_rabin(const BigNum& n, int k = 10) {
        if (n.cmp(BigNum(2)) < 0) return false;
        if (n.cmp(BigNum(2)) == 0 || n.cmp(BigNum(3)) == 0) return true;
        if (n.is_even()) return false;

        BigNum n_minus_1;
        n_minus_1.sub(n, BigNum(1));

        BigNum d = n_minus_1;
        uint32_t s = 0;
        while (d.is_even()) {
            d.shift_right(1);
            s++;
        }

        for (int i = 0; i < k; ++i) {
            std::vector<uint8_t> rand_bytes(n.bit_length() / 8 + 1, 0);
            SecureRandom::get_instance().generate(rand_bytes);
            BigNum a(std::span<const uint8_t>(rand_bytes), true);
            a = a.mod(n_minus_1);
            if (a.cmp(BigNum(2)) < 0) {
                a.add(a, BigNum(2));
            }

            BigNum x;
            x.mod_exp(a, d, n);

            if (x.cmp(BigNum(1)) == 0 || x.cmp(n_minus_1) == 0)
                continue;

            bool composite = true;
            for (uint32_t r = 1; r < s; ++r) {
                x.mod_exp(x, BigNum(2), n);
                if (x.cmp(n_minus_1) == 0) {
                    composite = false;
                    break;
                }
            }

            if (composite) return false;
        }

        return true;
    }

    BigNum generate_random_prime(uint32_t bits) {
        while (true) {
            std::vector<uint8_t> rand_bytes((bits + 7) / 8, 0);
            SecureRandom::get_instance().generate(rand_bytes);
            
            // Mask extra bits if bits is not a multiple of 8
            uint32_t rem = bits % 8;
            if (rem > 0) {
                rand_bytes[0] &= (1 << rem) - 1;
            }
            
            rand_bytes[0] |= (1 << (rem > 0 ? rem - 1 : 7)); // Ensure highest bit is set
            rand_bytes.back() |= 0x01; // Ensure odd
            
            BigNum candidate(std::span<const uint8_t>(rand_bytes), true);
            if (miller_rabin(candidate, 20)) {
                return candidate;
            }
        }
    }
}

void RsaPss::generate_keypair(PublicKey& pub, PrivateKey& priv, uint32_t bits) noexcept {
    // Basic bounds for RSA implementation loop
    // Generate primes p and q
    BigNum p = generate_random_prime(bits / 2);
    BigNum q = generate_random_prime(bits / 2);
    
    // n = p * q
    BigNum n;
    n.mul(p, q);

    // phi(n) = (p-1)*(q-1)
    BigNum p_minus_1 = p;
    p_minus_1.sub(p_minus_1, BigNum(1));
    BigNum q_minus_1 = q;
    q_minus_1.sub(q_minus_1, BigNum(1));
    
    BigNum phi;
    phi.mul(p_minus_1, q_minus_1);

    // standard public exponent e = 65537
    BigNum e(65537);

    // d = e^-1 mod phi(n)
    BigNum d;
    d.mod_inv(e, phi);

    pub.n = n;
    pub.e = e;

    priv.n = n;
    priv.d = d;
}

std::vector<uint8_t> RsaPss::mgf1(std::span<const uint8_t> mgf_seed, uint32_t mask_len) noexcept {
    std::vector<uint8_t> mask;
    mask.reserve(mask_len + 64);
    
    uint32_t counter = 0;
    while (mask.size() < mask_len) {
        Sha512 sha;
        sha.update(mgf_seed);
        
        uint8_t c_bytes[4];
        c_bytes[0] = (counter >> 24) & 0xFF;
        c_bytes[1] = (counter >> 16) & 0xFF;
        c_bytes[2] = (counter >> 8) & 0xFF;
        c_bytes[3] = counter & 0xFF;
        
        sha.update(std::span<const uint8_t>(c_bytes, 4));
        
        uint8_t out[64];
        sha.finalize(std::span<uint8_t, 64>(out, 64));
        mask.insert(mask.end(), out, out + 64);
        counter++;
    }
    
    mask.resize(mask_len);
    return mask;
}

std::vector<uint8_t> RsaPss::sign(
    std::span<const uint8_t> message,
    const PrivateKey& priv) noexcept 
{
    // 1. Hash the message M -> mHash
    Sha512 sha_m;
    sha_m.update(message);
    uint8_t m_hash[64];
    sha_m.finalize(std::span<uint8_t, 64>(m_hash, 64));

    // 2. Generate random salt (64 bytes for SHA512)
    uint8_t salt[64];
    SecureRandom::get_instance().generate(salt);

    // 3. M' = (0x)00 00 00 00 00 00 00 00 || mHash || salt
    uint8_t m_prime[8 + 64 + 64];
    std::memset(m_prime, 0, 8);
    std::memcpy(m_prime + 8, m_hash, 64);
    std::memcpy(m_prime + 72, salt, 64);

    // 4. H = Hash(M')
    Sha512 sha_h;
    sha_h.update(std::span<const uint8_t>(m_prime, sizeof(m_prime)));
    uint8_t H[64];
    sha_h.finalize(std::span<uint8_t, 64>(H, 64));

    // 5. Generate DB = PS || 0x01 || salt
    size_t em_len = (priv.n.bit_length() + 7) / 8;
    if (em_len < 64 + 64 + 2) return {};

    size_t ps_len = em_len - 64 - 64 - 2;
    std::vector<uint8_t> db(em_len - 64 - 1, 0);
    std::memset(db.data(), 0, ps_len);
    db[ps_len] = 0x01;
    std::memcpy(db.data() + ps_len + 1, salt, 64);

    // 6. dbMask = MGF1(H, emLen - hLen - 1)
    std::vector<uint8_t> db_mask = mgf1(std::span<const uint8_t>(H, 64), db.size());

    // 7. maskedDB = DB xor dbMask
    for (size_t i = 0; i < db.size(); ++i) {
        db[i] ^= db_mask[i];
    }
    
    // Set leftmost bit to 0
    db[0] &= ~(0xFF << 8 * em_len - priv.n.bit_length() + 1);

    // 8. EM = maskedDB || H || 0xbc
    std::vector<uint8_t> em;
    em.reserve(em_len);
    em.insert(em.end(), db.begin(), db.end());
    em.insert(em.end(), H, H + 64);
    em.push_back(0xBC);

    // RSA Core: s = EM^d mod n
    BigNum msg_bn(std::span<const uint8_t>(em), true);
    BigNum s;
    s.mod_exp(msg_bn, priv.d, priv.n);

    // Pad to length
    std::vector<uint8_t> raw_sig = s.to_bytes_be();
    std::vector<uint8_t> padded_sig(em_len, 0);
    if (raw_sig.size() <= em_len) {
        std::memcpy(padded_sig.data() + em_len - raw_sig.size(), raw_sig.data(), raw_sig.size());
    }
    return padded_sig;
}

bool RsaPss::verify(
    std::span<const uint8_t> signature,
    std::span<const uint8_t> message,
    const PublicKey& pub) noexcept
{
    // RSA Core: m = s^e mod n
    BigNum s_bn(signature, true);
    
    // Reject bounds check
    if (s_bn.cmp(pub.n) >= 0) return false;

    BigNum m_bn;
    m_bn.mod_exp(s_bn, pub.e, pub.n);

    std::vector<uint8_t> em = m_bn.to_bytes_be();
    size_t em_len = (pub.n.bit_length() + 7) / 8;
    
    // Pad EM to em_len
    std::vector<uint8_t> padded_em(em_len, 0);
    if (em.size() <= em_len) {
        std::memcpy(padded_em.data() + em_len - em.size(), em.data(), em.size());
    }
    em = std::move(padded_em);

    // 1. Verify last byte
    if (em.back() != 0xBC) return false;

    // 2. Extract maskedDB and H
    std::vector<uint8_t> masked_db(em.begin(), em.end() - 65);
    std::vector<uint8_t> H(em.end() - 65, em.end() - 1);

    // Check first byte logic
    if ((masked_db[0] & ~(0xFF >> (8 * em_len - pub.n.bit_length() + 1))) != 0) {
        return false;
    }

    // 3. dbMask = MGF1(H, emLen - hLen - 1)
    std::vector<uint8_t> db_mask = mgf1(std::span<const uint8_t>(H.data(), 64), masked_db.size());

    // 4. DB = maskedDB xor dbMask
    std::vector<uint8_t> db(masked_db.size());
    for (size_t i = 0; i < db.size(); ++i) {
        db[i] = masked_db[i] ^ db_mask[i];
    }
    db[0] &= (0xFF >> (8 * em_len - pub.n.bit_length() + 1));

    // 5. Check DB structure: PS || 0x01 || salt
    size_t ps_len = em_len - 64 - 64 - 2;
    for (size_t i = 0; i < ps_len; ++i) {
        if (db[i] != 0x00) return false;
    }
    if (db[ps_len] != 0x01) return false;

    // 6. Extract salt
    std::vector<uint8_t> salt(db.begin() + ps_len + 1, db.end());

    // 7. Hash message M
    Sha512 sha_m;
    sha_m.update(message);
    uint8_t m_hash[64];
    sha_m.finalize(std::span<uint8_t, 64>(m_hash, 64));

    // 8. M' = (0x)00 00 00 00 00 00 00 00 || mHash || salt
    uint8_t m_prime[8 + 64 + 64];
    std::memset(m_prime, 0, 8);
    std::memcpy(m_prime + 8, m_hash, 64);
    std::memcpy(m_prime + 72, salt.data(), 64);

    // 9. H' = Hash(M')
    Sha512 sha_h;
    sha_h.update(std::span<const uint8_t>(m_prime, sizeof(m_prime)));
    uint8_t H_prime[64];
    sha_h.finalize(std::span<uint8_t, 64>(H_prime, 64));

    // 10. Check H == H'
    return std::memcmp(H.data(), H_prime, 64) == 0;
}

} // namespace nit::crypto::osnova
