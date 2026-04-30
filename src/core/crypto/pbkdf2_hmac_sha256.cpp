#include "pbkdf2_hmac_sha256.h"
#include "hmac_sha256.h"
#include <cstring>
#include <array>

namespace nit::crypto::osnova {

void Pbkdf2HmacSha256::derive_key(
    std::span<uint8_t> out,
    std::span<const uint8_t> password,
    std::span<const uint8_t> salt,
    uint32_t iterations) noexcept 
{
    if (out.empty()) return;
    if (iterations == 0) return;

    constexpr size_t HASH_LEN = HmacSha256::MAC_SIZE;
    uint32_t blocks = (out.size() + HASH_LEN - 1) / HASH_LEN;

    std::array<uint8_t, HASH_LEN> U;
    std::array<uint8_t, HASH_LEN> T;

    size_t out_offset = 0;

    for (uint32_t i = 1; i <= blocks; ++i) {
        std::vector<uint8_t> salt_block;
        salt_block.reserve(salt.size() + 4);
        salt_block.insert(salt_block.end(), salt.begin(), salt.end());
        
        salt_block.push_back(static_cast<uint8_t>((i >> 24) & 0xFF));
        salt_block.push_back(static_cast<uint8_t>((i >> 16) & 0xFF));
        salt_block.push_back(static_cast<uint8_t>((i >> 8) & 0xFF));
        salt_block.push_back(static_cast<uint8_t>(i & 0xFF));

        HmacSha256::compute(U, password, salt_block);
        std::memcpy(T.data(), U.data(), HASH_LEN);

        for (uint32_t j = 1; j < iterations; ++j) {
            std::array<uint8_t, HASH_LEN> next_U;
            HmacSha256::compute(next_U, password, U);
            
            for (size_t k = 0; k < HASH_LEN; ++k) {
                T[k] ^= next_U[k];
            }
            std::memcpy(U.data(), next_U.data(), HASH_LEN);
        }

        size_t to_copy = std::min(HASH_LEN, out.size() - out_offset);
        std::memcpy(out.data() + out_offset, T.data(), to_copy);
        out_offset += to_copy;
    }

    std::memset(U.data(), 0, U.size());
    std::memset(T.data(), 0, T.size());
}

} // namespace nit::crypto::osnova
