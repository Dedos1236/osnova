#include "hkdf_sha512.h"
#include "hmac_sha512.h"
#include <cstring>
#include <array>

namespace nit::crypto::osnova {

void HkdfSha512::extract(
    std::span<uint8_t, HASH_LEN> prk,
    std::span<const uint8_t> salt,
    std::span<const uint8_t> ikm) noexcept 
{
    if (salt.empty()) {
        std::array<uint8_t, HASH_LEN> default_salt = {0};
        HmacSha512::compute(prk, default_salt, ikm);
    } else {
        HmacSha512::compute(prk, salt, ikm);
    }
}

void HkdfSha512::expand(
    std::span<uint8_t> okm,
    std::span<const uint8_t, HASH_LEN> prk,
    std::span<const uint8_t> info) noexcept 
{
    if (okm.empty()) return;

    size_t num_blocks = (okm.size() + HASH_LEN - 1) / HASH_LEN;
    if (num_blocks > 255) {
        return; // HKDF expansion limited to 255 * HashLen bytes
    }

    std::array<uint8_t, HASH_LEN> t = {0};
    size_t t_len = 0;
    size_t okm_offset = 0;

    for (uint8_t i = 1; i <= static_cast<uint8_t>(num_blocks); ++i) {
        std::vector<uint8_t> hmac_input;
        hmac_input.reserve(t_len + info.size() + 1);
        
        if (t_len > 0) {
            hmac_input.insert(hmac_input.end(), t.begin(), t.begin() + t_len);
        }
        hmac_input.insert(hmac_input.end(), info.begin(), info.end());
        hmac_input.push_back(i);

        HmacSha512::compute(t, prk, hmac_input);
        t_len = HASH_LEN;

        size_t to_copy = std::min(static_cast<size_t>(HASH_LEN), okm.size() - okm_offset);
        std::memcpy(okm.data() + okm_offset, t.data(), to_copy);
        okm_offset += to_copy;
    }

    std::memset(t.data(), 0, t.size());
}

void HkdfSha512::derive_key(
    std::span<uint8_t> okm,
    std::span<const uint8_t> ikm,
    std::span<const uint8_t> salt,
    std::span<const uint8_t> info) noexcept 
{
    std::array<uint8_t, HASH_LEN> prk;
    extract(prk, salt, ikm);
    expand(okm, prk, info);
    std::memset(prk.data(), 0, prk.size());
}

} // namespace nit::crypto::osnova
