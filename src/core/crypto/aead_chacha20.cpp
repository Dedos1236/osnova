#include "aead_chacha20.h"
#include <cstring>
#include <bit>

namespace nit::crypto::osnova {

namespace {
    inline void store64_le(uint8_t* dst, uint64_t w) noexcept {
        if constexpr (std::endian::native == std::endian::little) {
            std::memcpy(dst, &w, sizeof(w));
        } else {
            dst[0] = (uint8_t)(w);
            dst[1] = (uint8_t)(w >> 8);
            dst[2] = (uint8_t)(w >> 16);
            dst[3] = (uint8_t)(w >> 24);
            dst[4] = (uint8_t)(w >> 32);
            dst[5] = (uint8_t)(w >> 40);
            dst[6] = (uint8_t)(w >> 48);
            dst[7] = (uint8_t)(w >> 56);
        }
    }
}

void ChaCha20Poly1305::pad16_update(Poly1305& poly, size_t length) noexcept {
    size_t rem = length % 16;
    if (rem != 0) {
        uint8_t pad[16] = {0};
        poly.update(std::span<const uint8_t>(pad, 16 - rem));
    }
}

void ChaCha20Poly1305::length_update(Poly1305& poly, size_t aad_len, size_t ct_len) noexcept {
    uint8_t len_block[16];
    store64_le(len_block, aad_len);
    store64_le(len_block + 8, ct_len);
    poly.update(std::span<const uint8_t>(len_block, 16));
}

bool ChaCha20Poly1305::constant_time_eq(std::span<const uint8_t, MAC_SIZE> a, std::span<const uint8_t, MAC_SIZE> b) noexcept {
    uint8_t acc = 0;
    for (size_t i = 0; i < MAC_SIZE; ++i) {
        acc |= (a[i] ^ b[i]);
    }
    return acc == 0;
}

void ChaCha20Poly1305::encrypt(
    std::span<const uint8_t, KEY_SIZE> key,
    std::span<const uint8_t, NONCE_SIZE> nonce,
    std::span<const uint8_t> aad,
    std::span<const uint8_t> plaintext,
    std::span<uint8_t> ciphertext,
    std::span<uint8_t, MAC_SIZE> mac) noexcept 
{
    // 1. Generate Poly1305 Key using ChaCha20 Block 0
    ChaCha20 chacha(key, nonce, 0);
    uint8_t poly_key_buf[64];
    chacha.get_keystream_block(poly_key_buf);
    
    Poly1305 poly(std::span<const uint8_t, 32>(poly_key_buf, 32));
    std::memset(poly_key_buf, 0, sizeof(poly_key_buf)); // wipe block 0

    // 2. Encrypt plaintext (ChaCha20 counter starts at 1 implicitly since get_keystream_block incremented it)
    chacha.process_bytes(plaintext, ciphertext);

    // 3. Calculate MAC over AAD and Ciphertext
    if (!aad.empty()) {
        poly.update(aad);
        pad16_update(poly, aad.size());
    }

    if (!ciphertext.empty()) {
        poly.update(ciphertext);
        pad16_update(poly, ciphertext.size());
    }

    length_update(poly, aad.size(), ciphertext.size());
    poly.finalize(mac);
}

bool ChaCha20Poly1305::decrypt(
    std::span<const uint8_t, KEY_SIZE> key,
    std::span<const uint8_t, NONCE_SIZE> nonce,
    std::span<const uint8_t> aad,
    std::span<const uint8_t> ciphertext,
    std::span<const uint8_t, MAC_SIZE> in_mac,
    std::span<uint8_t> plaintext) noexcept 
{
    // 1. Generate Poly1305 Key
    ChaCha20 chacha(key, nonce, 0);
    uint8_t poly_key_buf[64];
    chacha.get_keystream_block(poly_key_buf);
    
    Poly1305 poly(std::span<const uint8_t, 32>(poly_key_buf, 32));
    std::memset(poly_key_buf, 0, sizeof(poly_key_buf));

    // 2. Authenticate BEFORE Decrypting to prevent Chosen Ciphertext Attacks (CCA)
    if (!aad.empty()) {
        poly.update(aad);
        pad16_update(poly, aad.size());
    }

    if (!ciphertext.empty()) {
        poly.update(ciphertext);
        pad16_update(poly, ciphertext.size());
    }

    length_update(poly, aad.size(), ciphertext.size());
    
    uint8_t expected_mac[16];
    poly.finalize(std::span<uint8_t, 16>(expected_mac, 16));

    if (!constant_time_eq(in_mac, std::span<const uint8_t, 16>(expected_mac, 16))) {
        // AUTHENTICATION FAILED. Wipe any potential plaintext and exit.
        std::memset(plaintext.data(), 0, plaintext.size());
        return false;
    }

    // 3. MAC is valid, safely decrypt.
    chacha.process_bytes(ciphertext, plaintext);
    return true;
}

} // namespace nit::crypto::osnova
