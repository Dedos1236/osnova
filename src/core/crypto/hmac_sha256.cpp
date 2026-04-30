#include "hmac_sha256.h"
#include "sha256.h"
#include <cstring>
#include <vector>

namespace nit::crypto::osnova {

void HmacSha256::compute(
    std::span<uint8_t, DIGEST_SIZE> mac,
    std::span<const uint8_t> key,
    std::span<const uint8_t> message) noexcept 
{
    uint8_t k_block[BLOCK_SIZE];
    std::memset(k_block, 0, BLOCK_SIZE);
    
    if (key.size() > BLOCK_SIZE) {
        Sha256 hash;
        hash.update(key);
        uint8_t k_hash[DIGEST_SIZE];
        hash.finalize(std::span<uint8_t, DIGEST_SIZE>(k_hash, DIGEST_SIZE));
        std::memcpy(k_block, k_hash, DIGEST_SIZE);
    } else if (key.size() > 0) {
        std::memcpy(k_block, key.data(), key.size());
    }

    uint8_t o_pad[BLOCK_SIZE];
    uint8_t i_pad[BLOCK_SIZE];
    for (size_t i = 0; i < BLOCK_SIZE; i++) {
        o_pad[i] = k_block[i] ^ 0x5C;
        i_pad[i] = k_block[i] ^ 0x36;
    }

    // Inner hash
    Sha256 inner_hash;
    inner_hash.update(std::span<const uint8_t>(i_pad, BLOCK_SIZE));
    inner_hash.update(message);
    uint8_t inner_digest[DIGEST_SIZE];
    inner_hash.finalize(std::span<uint8_t, DIGEST_SIZE>(inner_digest, DIGEST_SIZE));

    // Outer hash
    Sha256 outer_hash;
    outer_hash.update(std::span<const uint8_t>(o_pad, BLOCK_SIZE));
    outer_hash.update(std::span<const uint8_t>(inner_digest, DIGEST_SIZE));
    outer_hash.finalize(mac);
}

} // namespace nit::crypto::osnova
