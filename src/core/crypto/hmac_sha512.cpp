#include "hmac_sha512.h"
#include "sha512.h"
#include <cstring>
#include <array>

namespace nit::crypto::osnova {

void HmacSha512::compute(
    std::span<uint8_t, MAC_SIZE> mac_out,
    std::span<const uint8_t> key,
    std::span<const uint8_t> data) noexcept 
{
    std::array<uint8_t, Sha512::BLOCK_SIZE> k_block = {0};

    if (key.size() > Sha512::BLOCK_SIZE) {
        Sha512::hash(key, std::span<uint8_t, 64>(k_block.data(), 64));
    } else {
        std::memcpy(k_block.data(), key.data(), key.size());
    }

    std::array<uint8_t, Sha512::BLOCK_SIZE> o_key_pad;
    std::array<uint8_t, Sha512::BLOCK_SIZE> i_key_pad;

    for (size_t i = 0; i < Sha512::BLOCK_SIZE; ++i) {
        o_key_pad[i] = k_block[i] ^ 0x5c;
        i_key_pad[i] = k_block[i] ^ 0x36;
    }

    Sha512 inner_sha;
    inner_sha.update(i_key_pad);
    inner_sha.update(data);
    
    std::array<uint8_t, Sha512::DIGEST_SIZE> inner_hash;
    inner_sha.finalize(inner_hash);

    Sha512 outer_sha;
    outer_sha.update(o_key_pad);
    outer_sha.update(inner_hash);
    
    outer_sha.finalize(mac_out);

    std::memset(k_block.data(),  0, k_block.size());
    std::memset(i_key_pad.data(), 0, i_key_pad.size());
    std::memset(o_key_pad.data(), 0, o_key_pad.size());
    std::memset(inner_hash.data(), 0, inner_hash.size());
}

} // namespace nit::crypto::osnova
