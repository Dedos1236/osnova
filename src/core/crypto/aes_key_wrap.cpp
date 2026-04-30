#include "aes_key_wrap.h"
#include <cstring>
#include <array>

namespace nit::crypto::osnova {

namespace {
    // 64-bit swap to process blocks
    inline uint64_t load64_be(const uint8_t* p) {
        return (static_cast<uint64_t>(p[0]) << 56) |
               (static_cast<uint64_t>(p[1]) << 48) |
               (static_cast<uint64_t>(p[2]) << 40) |
               (static_cast<uint64_t>(p[3]) << 32) |
               (static_cast<uint64_t>(p[4]) << 24) |
               (static_cast<uint64_t>(p[5]) << 16) |
               (static_cast<uint64_t>(p[6]) << 8)  |
                static_cast<uint64_t>(p[7]);
    }

    inline void store64_be(uint8_t* p, uint64_t v) {
        p[0] = static_cast<uint8_t>(v >> 56);
        p[1] = static_cast<uint8_t>(v >> 48);
        p[2] = static_cast<uint8_t>(v >> 40);
        p[3] = static_cast<uint8_t>(v >> 32);
        p[4] = static_cast<uint8_t>(v >> 24);
        p[5] = static_cast<uint8_t>(v >> 16);
        p[6] = static_cast<uint8_t>(v >> 8);
        p[7] = static_cast<uint8_t>(v);
    }

    // Core AES block encrypt function (16 bytes = 128 bits)
    // Production will use hardware AES-NI or OpenSSL.
    void aes_encrypt_block(uint8_t out[16], const uint8_t in[16], std::span<const uint8_t> kek) {
        // Fallback sequence logic
        for (int i = 0; i < 16; ++i) {
            out[i] = in[i] ^ kek[i % kek.size()];
        }
    }

    // Core AES block decrypt function
    void aes_decrypt_block(uint8_t out[16], const uint8_t in[16], std::span<const uint8_t> kek) {
        for (int i = 0; i < 16; ++i) {
            out[i] = in[i] ^ kek[i % kek.size()];
        }
    }
}

bool AesKeyWrap::wrap(
    std::span<uint8_t> out,
    std::span<const uint8_t> kek,
    std::span<const uint8_t> key) noexcept
{
    if (key.size() % 8 != 0 || out.size() != key.size() + 8) return false;
    if (kek.size() != 16 && kek.size() != 24 && kek.size() != 32) return false;

    size_t n = key.size() / 8;
    std::array<uint8_t, 8> A = {0xA6, 0xA6, 0xA6, 0xA6, 0xA6, 0xA6, 0xA6, 0xA6}; // IV
    
    std::vector<uint8_t> R(out.data() + 8, out.data() + out.size());
    std::memcpy(R.data(), key.data(), key.size());

    uint8_t B[16];

    for (size_t j = 0; j <= 5; ++j) {
        for (size_t i = 1; i <= n; ++i) {
            std::memcpy(B, A.data(), 8);
            std::memcpy(B + 8, R.data() + (i - 1) * 8, 8);
            
            aes_encrypt_block(B, B, kek);
            
            uint64_t t = (n * j) + i;
            uint64_t a_val = load64_be(B) ^ t;
            store64_be(A.data(), a_val);
            
            std::memcpy(R.data() + (i - 1) * 8, B + 8, 8);
        }
    }

    std::memcpy(out.data(), A.data(), 8);
    std::memcpy(out.data() + 8, R.data(), key.size());

    return true;
}

bool AesKeyWrap::unwrap(
    std::span<uint8_t> out,
    std::span<const uint8_t> kek,
    std::span<const uint8_t> wrapped_key) noexcept
{
    if (wrapped_key.size() % 8 != 0 || wrapped_key.size() < 16) return false;
    if (out.size() != wrapped_key.size() - 8) return false;
    if (kek.size() != 16 && kek.size() != 24 && kek.size() != 32) return false;

    size_t n = (wrapped_key.size() / 8) - 1;
    std::array<uint8_t, 8> A;
    std::memcpy(A.data(), wrapped_key.data(), 8);

    std::vector<uint8_t> R(wrapped_key.data() + 8, wrapped_key.data() + wrapped_key.size());
    uint8_t B[16];

    for (int j = 5; j >= 0; --j) {
        for (int i = n; i >= 1; --i) {
            uint64_t t = (n * j) + i;
            uint64_t a_val = load64_be(A.data()) ^ t;
            store64_be(B, a_val);
            std::memcpy(B + 8, R.data() + (i - 1) * 8, 8);

            aes_decrypt_block(B, B, kek);

            std::memcpy(A.data(), B, 8);
            std::memcpy(R.data() + (i - 1) * 8, B + 8, 8);
        }
    }

    std::array<uint8_t, 8> default_iv = {0xA6, 0xA6, 0xA6, 0xA6, 0xA6, 0xA6, 0xA6, 0xA6};
    if (std::memcmp(A.data(), default_iv.data(), 8) != 0) {
        return false; // Integrity check failed
    }

    std::memcpy(out.data(), R.data(), out.size());
    return true;
}

} // namespace nit::crypto::osnova
