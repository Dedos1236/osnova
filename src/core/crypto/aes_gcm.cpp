#include "aes_gcm.h"
#include <cstring>
#include <bit>

namespace nit::crypto::osnova {

namespace {

    // AES S-Box
    const uint8_t s_box[256] = {
        0x63, 0x7c, 0x77, 0x7b, 0xf2, 0x6b, 0x6f, 0xc5, 0x30, 0x01, 0x67, 0x2b, 0xfe, 0xd7, 0xab, 0x76,
        0xca, 0x82, 0xc9, 0x7d, 0xfa, 0x59, 0x47, 0xf0, 0xad, 0xd4, 0xa2, 0xaf, 0x9c, 0xa4, 0x72, 0xc0,
        0xb7, 0xfd, 0x93, 0x26, 0x36, 0x3f, 0xf7, 0xcc, 0x34, 0xa5, 0xe5, 0xf1, 0x71, 0xd8, 0x31, 0x15,
        0x04, 0xc7, 0x23, 0xc3, 0x18, 0x96, 0x05, 0x9a, 0x07, 0x12, 0x80, 0xe2, 0xeb, 0x27, 0xb2, 0x75,
        0x09, 0x83, 0x2c, 0x1a, 0x1b, 0x6e, 0x5a, 0xa0, 0x52, 0x3b, 0xd6, 0xb3, 0x29, 0xe3, 0x2f, 0x84,
        0x53, 0xd1, 0x00, 0xed, 0x20, 0xfc, 0xb1, 0x5b, 0x6a, 0xcb, 0xbe, 0x39, 0x4a, 0x4c, 0x58, 0xcf,
        0xd0, 0xef, 0xaa, 0xfb, 0x43, 0x4d, 0x33, 0x85, 0x45, 0xf9, 0x02, 0x7f, 0x50, 0x3c, 0x9f, 0xa8,
        0x51, 0xa3, 0x40, 0x8f, 0x92, 0x9d, 0x38, 0xf5, 0xbc, 0xb6, 0xda, 0x21, 0x10, 0xff, 0xf3, 0xd2,
        0xcd, 0x0c, 0x13, 0xec, 0x5f, 0x97, 0x44, 0x17, 0xc4, 0xa7, 0x7e, 0x3d, 0x64, 0x5d, 0x19, 0x73,
        0x60, 0x81, 0x4f, 0xdc, 0x22, 0x2a, 0x90, 0x88, 0x46, 0xee, 0xb8, 0x14, 0xde, 0x5e, 0x0b, 0xdb,
        0xe0, 0x32, 0x3a, 0x0a, 0x49, 0x06, 0x24, 0x5c, 0xc2, 0xd3, 0xac, 0x62, 0x91, 0x95, 0xe4, 0x79,
        0xe7, 0xc8, 0x37, 0x6d, 0x8d, 0xd5, 0x4e, 0xa9, 0x6c, 0x56, 0xf4, 0xea, 0x65, 0x7a, 0xae, 0x08,
        0xba, 0x78, 0x25, 0x2e, 0x1c, 0xa6, 0xb4, 0xc6, 0xe8, 0xdd, 0x74, 0x1f, 0x4b, 0xbd, 0x8b, 0x8a,
        0x70, 0x3e, 0xb5, 0x66, 0x48, 0x03, 0xf6, 0x0e, 0x61, 0x35, 0x57, 0xb9, 0x86, 0xc1, 0x1d, 0x9e,
        0xe1, 0xf8, 0x98, 0x11, 0x69, 0xd9, 0x8e, 0x94, 0x9b, 0x1e, 0x87, 0xe9, 0xce, 0x55, 0x28, 0xdf,
        0x8c, 0xa1, 0x89, 0x0d, 0xbf, 0xe6, 0x42, 0x68, 0x41, 0x99, 0x2d, 0x0f, 0xb0, 0x54, 0xbb, 0x16
    };

    // AES Round Constants
    const uint32_t rcon[11] = {
        0x00000000, 0x01000000, 0x02000000, 0x04000000, 0x08000000,
        0x10000000, 0x20000000, 0x40000000, 0x80000000, 0x1B000000, 0x36000000
    };

    inline uint32_t rotWord(uint32_t word) {
        return (word << 8) | (word >> 24);
    }

    inline uint32_t subWord(uint32_t word) {
        return (s_box[(word >> 24) & 0xFF] << 24) |
               (s_box[(word >> 16) & 0xFF] << 16) |
               (s_box[(word >> 8) & 0xFF] << 8) |
               (s_box[word & 0xFF]);
    }

    // Multiply by 2 in GF(2^8)
    inline uint8_t xtime(uint8_t x) {
        return (x << 1) ^ (((x >> 7) & 1) * 0x1B);
    }

    inline uint64_t load64_be(const uint8_t* p) {
        if constexpr (std::endian::native == std::endian::big) {
            uint64_t v;
            std::memcpy(&v, p, 8);
            return v;
        } else {
            return ((uint64_t)p[0] << 56) | ((uint64_t)p[1] << 48) | ((uint64_t)p[2] << 40) | ((uint64_t)p[3] << 32) |
                   ((uint64_t)p[4] << 24) | ((uint64_t)p[5] << 16) | ((uint64_t)p[6] << 8) | ((uint64_t)p[7]);
        }
    }

    inline void store64_be(uint8_t* p, uint64_t v) {
        if constexpr (std::endian::native == std::endian::big) {
            std::memcpy(p, &v, 8);
        } else {
            p[0] = v >> 56; p[1] = v >> 48; p[2] = v >> 40; p[3] = v >> 32;
            p[4] = v >> 24; p[5] = v >> 16; p[6] = v >> 8; p[7] = v;
        }
    }
}

void Aes256Gcm::aes256_key_expansion(const uint8_t* key, uint32_t* round_keys) noexcept {
    for (int i = 0; i < 8; i++) {
        round_keys[i] = (key[4 * i] << 24) | (key[4 * i + 1] << 16) | (key[4 * i + 2] << 8) | key[4 * i + 3];
    }
    for (int i = 8; i < 60; i++) {
        uint32_t temp = round_keys[i - 1];
        if (i % 8 == 0) {
            temp = subWord(rotWord(temp)) ^ rcon[i / 8];
        } else if (i % 8 == 4) {
            temp = subWord(temp);
        }
        round_keys[i] = round_keys[i - 8] ^ temp;
    }
}

// Emulates a generic software AES operation (ShiftRows, SubBytes, MixColumns, AddRoundKey)
// Specifically implemented here to achieve purely zero-dependency OSNOVA target scope
void Aes256Gcm::aes256_encrypt_block(const uint8_t* in, uint8_t* out, const uint32_t* round_keys) noexcept {
    uint8_t state[16];
    std::memcpy(state, in, 16);

    // Initial AddRoundKey
    for (int i = 0; i < 16; i++) {
        state[i] ^= (round_keys[i / 4] >> (24 - 8 * (i % 4))) & 0xFF;
    }

    for (int round = 1; round < 14; round++) {
        // SubBytes
        for (int i = 0; i < 16; i++) state[i] = s_box[state[i]];

        // ShiftRows
        uint8_t tmp[16];
        tmp[0]  = state[0]; tmp[4]  = state[4]; tmp[8]  = state[8]; tmp[12] = state[12];
        tmp[1]  = state[5]; tmp[5]  = state[9]; tmp[9]  = state[13]; tmp[13] = state[1];
        tmp[2]  = state[10]; tmp[6] = state[14]; tmp[10] = state[2]; tmp[14] = state[6];
        tmp[3]  = state[15]; tmp[7] = state[3]; tmp[11] = state[7]; tmp[15] = state[11];
        std::memcpy(state, tmp, 16);

        // MixColumns
        for (int i = 0; i < 4; i++) {
            uint8_t a = state[i * 4];
            uint8_t b = state[i * 4 + 1];
            uint8_t c = state[i * 4 + 2];
            uint8_t d = state[i * 4 + 3];
            uint8_t a_b_c_d = a ^ b ^ c ^ d;

            state[i * 4]     = a ^ a_b_c_d ^ xtime(a ^ b);
            state[i * 4 + 1] = b ^ a_b_c_d ^ xtime(b ^ c);
            state[i * 4 + 2] = c ^ a_b_c_d ^ xtime(c ^ d);
            state[i * 4 + 3] = d ^ a_b_c_d ^ xtime(d ^ a);
        }

        // AddRoundKey
        for (int i = 0; i < 16; i++) {
            state[i] ^= (round_keys[round * 4 + (i / 4)] >> (24 - 8 * (i % 4))) & 0xFF;
        }
    }

    // Final round
    for (int i = 0; i < 16; i++) state[i] = s_box[state[i]];

    uint8_t tmp[16];
    tmp[0]  = state[0]; tmp[4]  = state[4]; tmp[8]  = state[8]; tmp[12] = state[12];
    tmp[1]  = state[5]; tmp[5]  = state[9]; tmp[9]  = state[13]; tmp[13] = state[1];
    tmp[2]  = state[10]; tmp[6] = state[14]; tmp[10] = state[2]; tmp[14] = state[6];
    tmp[3]  = state[15]; tmp[7] = state[3]; tmp[11] = state[7]; tmp[15] = state[11];
    std::memcpy(state, tmp, 16);

    for (int i = 0; i < 16; i++) {
        state[i] ^= (round_keys[14 * 4 + (i / 4)] >> (24 - 8 * (i % 4))) & 0xFF;
    }

    std::memcpy(out, state, 16);
}

void Aes256Gcm::gf128_mul(uint64_t x[2], const uint64_t y[2]) noexcept {
    uint64_t z[2] = {0, 0};
    uint64_t v[2] = {y[0], y[1]};

    for (int i = 0; i < 64; i++) {
        if ((x[0] >> (63 - i)) & 1) {
            z[0] ^= v[0];
            z[1] ^= v[1];
        }
        uint64_t lsb = v[1] & 1;
        v[1] = (v[0] << 63) | (v[1] >> 1);
        v[0] = v[0] >> 1;
        if (lsb) v[0] ^= 0xE100000000000000ULL;
    }
    for (int i = 0; i < 64; i++) {
        if ((x[1] >> (63 - i)) & 1) {
            z[0] ^= v[0];
            z[1] ^= v[1];
        }
        uint64_t lsb = v[1] & 1;
        v[1] = (v[0] << 63) | (v[1] >> 1);
        v[0] = v[0] >> 1;
        if (lsb) v[0] ^= 0xE100000000000000ULL;
    }

    x[0] = z[0];
    x[1] = z[1];
}

void Aes256Gcm::encrypt(
    std::span<uint8_t> ciphertext,
    std::span<uint8_t, TAG_SIZE> tag,
    std::span<const uint8_t> plaintext,
    std::span<const uint8_t> ad,
    std::span<const uint8_t, KEY_SIZE> key,
    std::span<const uint8_t, NONCE_SIZE> nonce) noexcept 
{
    // Standard software implementation for AEAD wrapper. 
    // Uses generic software fallbacks when hardware AES-NI instructions are unavailable.
    
    uint32_t round_keys[60];
    aes256_key_expansion(key.data(), round_keys);

    uint8_t counter[16];
    std::memcpy(counter, nonce.data(), 12);
    counter[12] = 0; counter[13] = 0; counter[14] = 0; counter[15] = 1;

    uint8_t j0[16];
    aes256_encrypt_block(counter, j0, round_keys);

    // Increment counter manually
    auto inc32 = [&counter](){
        uint32_t c = (counter[12]<<24) | (counter[13]<<16) | (counter[14]<<8) | counter[15];
        c++;
        counter[12] = c>>24; counter[13] = c>>16; counter[14] = c>>8; counter[15] = c;
    };

    size_t length = plaintext.size();
    for (size_t i = 0; i < length; i += 16) {
        inc32();
        uint8_t pad[16];
        aes256_encrypt_block(counter, pad, round_keys);
        
        size_t block_len = std::min<size_t>(16, length - i);
        for (size_t j = 0; j < block_len; ++j) {
            ciphertext[i + j] = plaintext[i + j] ^ pad[j];
        }
    }

    // Standard TAG derivation using GHASH over AD and Ciphertext
    uint8_t hash_key[16] = {0};
    aes256_encrypt_block(hash_key, hash_key, round_keys); // encrypt 0 block to get H

    uint64_t h_64[2];
    h_64[0] = load64_be(hash_key);
    h_64[1] = load64_be(hash_key + 8);

    uint64_t tag_state[2] = {0, 0};
    // Actual GCM GHASH over AD and Ciphertext
    auto ghash_update = [&](const uint8_t* data, size_t len) {
        for (size_t i = 0; i < len; i += 16) {
            uint8_t block[16] = {0};
            std::memcpy(block, data + i, std::min<size_t>(16, len - i));
            tag_state[0] ^= load64_be(block);
            tag_state[1] ^= load64_be(block + 8);
            gf128_mul(tag_state, h_64);
        }
    };

    ghash_update(ad.data(), ad.size());
    ghash_update(ciphertext.data(), ciphertext.size());
    
    // Mix lengths
    uint64_t l_ad = ad.size() * 8;
    uint64_t l_c = length * 8;
    tag_state[0] ^= l_ad;
    tag_state[1] ^= l_c;
    gf128_mul(tag_state, h_64);

    uint8_t s_block[16];
    store64_be(s_block, tag_state[0]);
    store64_be(s_block + 8, tag_state[1]);

    for (int i = 0; i < 16; ++i) {
        tag[i] = s_block[i] ^ j0[i];
    }
}

bool Aes256Gcm::decrypt(
    std::span<uint8_t> plaintext,
    std::span<const uint8_t> ciphertext,
    std::span<const uint8_t, TAG_SIZE> tag,
    std::span<const uint8_t> ad,
    std::span<const uint8_t, KEY_SIZE> key,
    std::span<const uint8_t, NONCE_SIZE> nonce) noexcept 
{
    // Derived counter logic equivalent to encrypt
    uint32_t round_keys[60];
    aes256_key_expansion(key.data(), round_keys);

    uint8_t counter[16];
    std::memcpy(counter, nonce.data(), 12);
    counter[12] = 0; counter[13] = 0; counter[14] = 0; counter[15] = 1;

    uint8_t j0[16];
    aes256_encrypt_block(counter, j0, round_keys);

    auto inc32 = [&counter](){
        uint32_t c = (counter[12]<<24) | (counter[13]<<16) | (counter[14]<<8) | counter[15];
        c++;
        counter[12] = c>>24; counter[13] = c>>16; counter[14] = c>>8; counter[15] = c;
    };

    size_t length = ciphertext.size();
    for (size_t i = 0; i < length; i += 16) {
        inc32();
        uint8_t pad[16];
        aes256_encrypt_block(counter, pad, round_keys);
        
        size_t block_len = std::min<size_t>(16, length - i);
        for (size_t j = 0; j < block_len; ++j) {
            plaintext[i + j] = ciphertext[i + j] ^ pad[j];
        }
    }

    uint8_t hash_key[16] = {0};
    aes256_encrypt_block(hash_key, hash_key, round_keys);

    uint64_t h_64[2];
    h_64[0] = load64_be(hash_key);
    h_64[1] = load64_be(hash_key + 8);

    uint64_t tag_state[2] = {0, 0};
    auto ghash_update = [&](const uint8_t* data, size_t len) {
        for (size_t i = 0; i < len; i += 16) {
            uint8_t block[16] = {0};
            std::memcpy(block, data + i, std::min<size_t>(16, len - i));
            tag_state[0] ^= load64_be(block);
            tag_state[1] ^= load64_be(block + 8);
            gf128_mul(tag_state, h_64);
        }
    };

    ghash_update(ad.data(), ad.size());
    ghash_update(ciphertext.data(), ciphertext.size());
    
    uint64_t l_ad = ad.size() * 8;
    uint64_t l_c = length * 8;
    tag_state[0] ^= l_ad;
    tag_state[1] ^= l_c;
    gf128_mul(tag_state, h_64);

    uint8_t s_block[16];
    store64_be(s_block, tag_state[0]);
    store64_be(s_block + 8, tag_state[1]);

    uint8_t computed_tag[16];
    for (int i = 0; i < 16; ++i) {
        computed_tag[i] = s_block[i] ^ j0[i];
    }

    uint8_t diff = 0;
    for (size_t i = 0; i < TAG_SIZE; ++i) {
        diff |= (computed_tag[i] ^ tag[i]);
    }

    if (diff != 0) {
        std::memset(plaintext.data(), 0, length);
        return false;
    }

    return true;
}

} // namespace nit::crypto::osnova
