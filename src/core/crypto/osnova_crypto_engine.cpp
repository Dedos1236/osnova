#include "osnova_crypto_engine.h"
#include "aead_chacha20.h"
#include "curve25519.h"
#include "hkdf.h"
#include "kyber768.h"
#include "secure_random.h"
#include <immintrin.h> // Example of hardware intrinsics inclusion
#include <cstring>
#include <mutex>

// Core interface over hardware security macros
// Optimized for direct binding with emscripten and native targets.

namespace nit::crypto::osnova {

struct OsnovaEngine::Impl {
    std::mutex rng_mtx;

    // Output secure random bytes using OS-level RNG and HMAC-DRBG
    void hw_random_bytes(std::span<std::byte> out) {
        std::span<uint8_t> out_u8(reinterpret_cast<uint8_t*>(out.data()), out.size());
        SecureRandom::get_instance().generate(out_u8);
    }

    // KDF: HKDF-SHA512 to combine X25519 and Kyber shared secrets
    void hkdf_combine(const std::array<std::byte, 32>& ss1, const std::array<std::byte, 32>& ss2, SymmetricKey& out) {
        // HKDF logical pipeline combining classic ECDH and post-quantum properties
        std::vector<uint8_t> ikm;
        ikm.reserve(64);
        ikm.insert(ikm.end(), reinterpret_cast<const uint8_t*>(ss1.data()), reinterpret_cast<const uint8_t*>(ss1.data()) + 32);
        ikm.insert(ikm.end(), reinterpret_cast<const uint8_t*>(ss2.data()), reinterpret_cast<const uint8_t*>(ss2.data()) + 32);
        
        std::array<uint8_t, 32> salt = {0}; // OSNOVA Default NULL salt for KEM combination
        std::array<uint8_t, 13> info = {'O', 'S', 'N', 'O', 'V', 'A', '_', 'H', 'Y', 'B', 'R', 'I', 'D'};
        
        HkdfSha512::derive_key(
            std::span<const uint8_t>(salt), 
            std::span<const uint8_t>(ikm), 
            std::span<const uint8_t>(info), 
            std::span<uint8_t>(reinterpret_cast<uint8_t*>(out.data()), 32)
        );
        
        // Secure wipe
        std::memset(ikm.data(), 0, ikm.capacity());
    }
};

OsnovaEngine::OsnovaEngine() : pimpl_(std::make_unique<Impl>()) {}
OsnovaEngine::~OsnovaEngine() = default;

std::expected<void, CryptoError> OsnovaEngine::generate_keypair(HybridPublicKey& pub, HybridSecretKey& sec) noexcept {
    // 1. Generate X25519 via our C++ core
    pimpl_->hw_random_bytes(sec.x25519_sk);
    
    std::span<uint8_t, 32> pub_out(reinterpret_cast<uint8_t*>(pub.x25519_pk.data()), 32);
    std::span<const uint8_t, 32> sk_in(reinterpret_cast<const uint8_t*>(sec.x25519_sk.data()), 32);
    Curve25519::generate_public_key(pub_out, sk_in);

    // 2. Generate Kyber768 (OQS / ML-KEM)
    std::array<uint8_t, 64> randomness;
    pimpl_->hw_random_bytes(std::span<std::byte>(reinterpret_cast<std::byte*>(randomness.data()), randomness.size()));
    
    std::span<uint8_t, 1184> pk_out(reinterpret_cast<uint8_t*>(pub.kyber_pk.data()), 1184);
    std::span<uint8_t, 2400> sk_out(reinterpret_cast<uint8_t*>(sec.kyber_sk.data()), 2400);
    Kyber768::generate_keypair(pk_out, sk_out, std::span<const uint8_t, 64>(randomness));

    return {};
}

std::expected<std::pair<HybridCiphertext, SymmetricKey>, CryptoError> OsnovaEngine::encapsulate(
    const HybridPublicKey& peer_pub) noexcept {
    
    HybridCiphertext ct;
    std::array<std::byte, 32> x25519_ss;
    std::array<std::byte, 32> kyber_ss;

    // 1. X25519 Ephemeral key generation & agreement
    std::array<std::byte, 32> ephemeral_sk;
    pimpl_->hw_random_bytes(ephemeral_sk);
    
    std::span<uint8_t, 32> ephem_pub(reinterpret_cast<uint8_t*>(ct.x25519_ephemeral_pk.data()), 32);
    std::span<const uint8_t, 32> ephem_sk_in(reinterpret_cast<const uint8_t*>(ephemeral_sk.data()), 32);
    Curve25519::generate_public_key(ephem_pub, ephem_sk_in);
    
    std::span<uint8_t, 32> ss_out(reinterpret_cast<uint8_t*>(x25519_ss.data()), 32);
    std::span<const uint8_t, 32> peer_pk_in(reinterpret_cast<const uint8_t*>(peer_pub.x25519_pk.data()), 32);
    Curve25519::scalarmult(ss_out, ephem_sk_in, peer_pk_in);

    // 2. Kyber768 Encapsulation
    std::array<uint8_t, 32> kyber_rand;
    pimpl_->hw_random_bytes(std::span<std::byte>(reinterpret_cast<std::byte*>(kyber_rand.data()), kyber_rand.size()));
    
    std::span<uint8_t, 1088> ct_out(reinterpret_cast<uint8_t*>(ct.kyber_ct.data()), 1088);
    std::span<uint8_t, 32> kss_out(reinterpret_cast<uint8_t*>(kyber_ss.data()), 32);
    std::span<const uint8_t, 1184> kpk_in(reinterpret_cast<const uint8_t*>(peer_pub.kyber_pk.data()), 1184);
    
    Kyber768::encapsulate(ct_out, kss_out, kpk_in, std::span<const uint8_t, 32>(kyber_rand));

    // 3. Key Derivation (Combine classic and PQ secrets)
    SymmetricKey final_ss;
    pimpl_->hkdf_combine(x25519_ss, kyber_ss, final_ss);

    return std::make_pair(ct, final_ss);
}

std::expected<SymmetricKey, CryptoError> OsnovaEngine::decapsulate(
    const HybridCiphertext& ct, const HybridSecretKey& my_sec) noexcept {
    
    std::array<std::byte, 32> x25519_ss;
    std::array<std::byte, 32> kyber_ss;

    // 1. X25519 agreement via C++ core
    std::span<uint8_t, 32> ss_out(reinterpret_cast<uint8_t*>(x25519_ss.data()), 32);
    std::span<const uint8_t, 32> my_sk_in(reinterpret_cast<const uint8_t*>(my_sec.x25519_sk.data()), 32);
    std::span<const uint8_t, 32> ephem_pk_in(reinterpret_cast<const uint8_t*>(ct.x25519_ephemeral_pk.data()), 32);
    Curve25519::scalarmult(ss_out, my_sk_in, ephem_pk_in);

    // 2. Kyber decapsulation
    std::span<uint8_t, 32> kss_out(reinterpret_cast<uint8_t*>(kyber_ss.data()), 32);
    std::span<const uint8_t, 1088> kct_in(reinterpret_cast<const uint8_t*>(ct.kyber_ct.data()), 1088);
    std::span<const uint8_t, 2400> ksk_in(reinterpret_cast<const uint8_t*>(my_sec.kyber_sk.data()), 2400);
    Kyber768::decapsulate(kss_out, kct_in, ksk_in);

    SymmetricKey final_ss;
    pimpl_->hkdf_combine(x25519_ss, kyber_ss, final_ss);
    return final_ss;
}

std::expected<size_t, CryptoError> OsnovaEngine::encrypt_in_place(
    std::span<std::byte> buffer, size_t pt_len, const SymmetricKey& key, const Nonce& nonce, std::span<const std::byte> aad) noexcept {
    
    if (buffer.size() < pt_len + OSNOVA_MAC_SIZE) {
        return std::unexpected(CryptoError::BufferTooSmall);
    }

    // Call native ChaCha20-Poly1305
    std::span<const uint8_t> plaintext(reinterpret_cast<const uint8_t*>(buffer.data()), pt_len);
    std::span<uint8_t> ciphertext(reinterpret_cast<uint8_t*>(buffer.data()), pt_len);
    std::span<uint8_t, 16> mac(reinterpret_cast<uint8_t*>(buffer.data() + pt_len), 16);
    
    std::span<const uint8_t, 32> key_u8(reinterpret_cast<const uint8_t*>(key.data()), 32);
    std::span<const uint8_t, 12> nonce_u8(reinterpret_cast<const uint8_t*>(nonce.data()), 12);
    std::span<const uint8_t> aad_u8(reinterpret_cast<const uint8_t*>(aad.data()), aad.size());

    ChaCha20Poly1305::encrypt(key_u8, nonce_u8, aad_u8, plaintext, ciphertext, mac);

    return pt_len + OSNOVA_MAC_SIZE;
}

std::expected<size_t, CryptoError> OsnovaEngine::decrypt_in_place(
    std::span<std::byte> buffer, size_t ct_len, const SymmetricKey& key, const Nonce& nonce, std::span<const std::byte> aad) noexcept {
    
    if (ct_len < OSNOVA_MAC_SIZE) {
        return std::unexpected(CryptoError::InvalidKeySize);
    }

    size_t pt_len = ct_len - OSNOVA_MAC_SIZE;

    std::span<const uint8_t> ciphertext(reinterpret_cast<const uint8_t*>(buffer.data()), pt_len);
    std::span<const uint8_t, 16> mac(reinterpret_cast<const uint8_t*>(buffer.data() + pt_len), 16);
    std::span<uint8_t> plaintext(reinterpret_cast<uint8_t*>(buffer.data()), pt_len);

    std::span<const uint8_t, 32> key_u8(reinterpret_cast<const uint8_t*>(key.data()), 32);
    std::span<const uint8_t, 12> nonce_u8(reinterpret_cast<const uint8_t*>(nonce.data()), 12);
    std::span<const uint8_t> aad_u8(reinterpret_cast<const uint8_t*>(aad.data()), aad.size());

    if (!ChaCha20Poly1305::decrypt(key_u8, nonce_u8, aad_u8, ciphertext, mac, plaintext)) {
        return std::unexpected(CryptoError::AuthenticationFailed);
    }

    return pt_len;
}

} // namespace nit::crypto::osnova
