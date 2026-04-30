#include "hkdf_sha256.h"
#include "hmac_sha256.h"
#include <cstring>
#include <algorithm>

namespace nit::crypto::osnova {

void HkdfSha256::extract(
    std::span<uint8_t, DIGEST_SIZE> prk,
    std::span<const uint8_t> salt,
    std::span<const uint8_t> ikm) noexcept
{
    const uint8_t default_salt[DIGEST_SIZE] = {0};
    if (salt.empty()) {
        HmacSha256::compute(prk, std::span<const uint8_t>(default_salt, DIGEST_SIZE), ikm);
    } else {
        HmacSha256::compute(prk, salt, ikm);
    }
}

void HkdfSha256::expand(
    std::span<uint8_t> okm,
    std::span<const uint8_t, DIGEST_SIZE> prk,
    std::span<const uint8_t> info) noexcept
{
    size_t length = okm.size();
    if (length == 0 || length > 255 * DIGEST_SIZE) return;

    size_t num_blocks = (length + DIGEST_SIZE - 1) / DIGEST_SIZE;
    uint8_t t_block[DIGEST_SIZE];
    size_t t_len = 0;

    std::vector<uint8_t> hmac_in;
    hmac_in.reserve(DIGEST_SIZE + info.size() + 1);

    size_t out_offset = 0;

    for (size_t i = 1; i <= num_blocks; ++i) {
        hmac_in.clear();
        if (t_len > 0) {
            hmac_in.insert(hmac_in.end(), t_block, t_block + t_len);
        }
        hmac_in.insert(hmac_in.end(), info.begin(), info.end());
        hmac_in.push_back(static_cast<uint8_t>(i));

        HmacSha256::compute(
            std::span<uint8_t, DIGEST_SIZE>(t_block, DIGEST_SIZE),
            prk,
            std::span<const uint8_t>(hmac_in)
        );
        t_len = DIGEST_SIZE;

        size_t to_copy = std::min<size_t>(DIGEST_SIZE, length - out_offset);
        std::memcpy(okm.data() + out_offset, t_block, to_copy);
        out_offset += to_copy;
    }
}

void HkdfSha256::derive_key(
    std::span<uint8_t> okm,
    std::span<const uint8_t> ikm,
    std::span<const uint8_t> salt,
    std::span<const uint8_t> info) noexcept
{
    uint8_t prk[DIGEST_SIZE];
    extract(std::span<uint8_t, DIGEST_SIZE>(prk, DIGEST_SIZE), salt, ikm);
    expand(okm, std::span<const uint8_t, DIGEST_SIZE>(prk, DIGEST_SIZE), info);
}

} // namespace nit::crypto::osnova
