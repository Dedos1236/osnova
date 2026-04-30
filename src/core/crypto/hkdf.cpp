#include "hkdf.h"
#include "sha512.h"
#include <cstring>
#include <vector>

namespace nit::crypto::osnova {

void HmacSha512::compute(
    std::span<const uint8_t> key,
    std::span<const uint8_t> data,
    std::span<uint8_t, DIGEST_SIZE> mac) noexcept 
{
    uint8_t k_block[Sha512::BLOCK_SIZE] = {0};
    
    if (key.size() > Sha512::BLOCK_SIZE) {
        Sha512::hash(key, std::span<uint8_t, DIGEST_SIZE>(k_block, DIGEST_SIZE));
    } else {
        std::memcpy(k_block, key.data(), key.size());
    }

    uint8_t i_key_pad[Sha512::BLOCK_SIZE];
    uint8_t o_key_pad[Sha512::BLOCK_SIZE];

    for (size_t i = 0; i < Sha512::BLOCK_SIZE; ++i) {
        i_key_pad[i] = k_block[i] ^ 0x36;
        o_key_pad[i] = k_block[i] ^ 0x5C;
    }

    Sha512 inner_sha;
    inner_sha.update(std::span<const uint8_t>(i_key_pad, Sha512::BLOCK_SIZE));
    inner_sha.update(data);
    
    uint8_t inner_hash[DIGEST_SIZE];
    inner_sha.finalize(std::span<uint8_t, DIGEST_SIZE>(inner_hash, DIGEST_SIZE));

    Sha512 outer_sha;
    outer_sha.update(std::span<const uint8_t>(o_key_pad, Sha512::BLOCK_SIZE));
    outer_sha.update(std::span<const uint8_t>(inner_hash, DIGEST_SIZE));
    outer_sha.finalize(mac);

    std::memset(k_block, 0, sizeof(k_block));
    std::memset(i_key_pad, 0, sizeof(i_key_pad));
    std::memset(o_key_pad, 0, sizeof(o_key_pad));
    std::memset(inner_hash, 0, sizeof(inner_hash));
}

void HkdfSha512::derive_key(
    std::span<const uint8_t> salt,
    std::span<const uint8_t> ikm,
    std::span<const uint8_t> info,
    std::span<uint8_t> okm) noexcept 
{
    // HKDF-Extract
    uint8_t prk[HmacSha512::DIGEST_SIZE];
    // If salt is not provided it is set to a string of HashLen zeros.
    if (salt.empty()) {
        uint8_t zeros[HmacSha512::DIGEST_SIZE] = {0};
        HmacSha512::compute(std::span<const uint8_t>(zeros, sizeof(zeros)), ikm, std::span<uint8_t, HmacSha512::DIGEST_SIZE>(prk, sizeof(prk)));
    } else {
        HmacSha512::compute(salt, ikm, std::span<uint8_t, HmacSha512::DIGEST_SIZE>(prk, sizeof(prk)));
    }

    // HKDF-Expand
    size_t length = okm.size();
    size_t n = (length + HmacSha512::DIGEST_SIZE - 1) / HmacSha512::DIGEST_SIZE;
    
    if (n > 255) return; // RFC 5869: OKM length cannot exceed 255 * HashLen

    uint8_t t[HmacSha512::DIGEST_SIZE] = {0};
    size_t t_len = 0;
    size_t offset = 0;

    for (uint8_t i = 1; i <= n; ++i) {
        // T(i) = HMAC-Hash(PRK, T(i-1) | info | i)
        
        // We use a dynamic array since info can be large, but for secure enclave this 
        // usually uses fixed size block updates. We will do a single buffer for simplicity here.
        std::vector<uint8_t> expand_in;
        expand_in.reserve(t_len + info.size() + 1);
        if (t_len > 0) expand_in.insert(expand_in.end(), t, t + t_len);
        expand_in.insert(expand_in.end(), info.data(), info.data() + info.size());
        expand_in.push_back(i);

        HmacSha512::compute(
            std::span<const uint8_t>(prk, sizeof(prk)), 
            std::span<const uint8_t>(expand_in.data(), expand_in.size()), 
            std::span<uint8_t, HmacSha512::DIGEST_SIZE>(t, sizeof(t))
        );
        t_len = HmacSha512::DIGEST_SIZE;

        size_t to_copy = (length - offset < t_len) ? length - offset : t_len;
        std::memcpy(okm.data() + offset, t, to_copy);
        offset += to_copy;
    }

    std::memset(prk, 0, sizeof(prk));
    std::memset(t, 0, sizeof(t));
}

} // namespace nit::crypto::osnova
