#include "hmac_drbg.h"
#include "hmac_sha256.h"
#include <cstring>
#include <array>

namespace nit::crypto::osnova {

void HmacDrbg::update(std::span<const uint8_t> provided_data) noexcept {
    update_multiple(provided_data, {}, {});
}

void HmacDrbg::update_multiple(
    std::span<const uint8_t> data1, 
    std::span<const uint8_t> data2, 
    std::span<const uint8_t> data3) noexcept 
{
    std::array<uint8_t, HmacSha256::MAC_SIZE> mac;
    std::vector<uint8_t> input;
    input.reserve(V.size() + 1 + data1.size() + data2.size() + data3.size());
    
    // Key = HMAC(Key, V || 0x00 || provided_data)
    input.insert(input.end(), V.begin(), V.end());
    input.push_back(0x00);
    if (!data1.empty()) input.insert(input.end(), data1.begin(), data1.end());
    if (!data2.empty()) input.insert(input.end(), data2.begin(), data2.end());
    if (!data3.empty()) input.insert(input.end(), data3.begin(), data3.end());
    
    HmacSha256::compute(mac, Key, input);
    Key.assign(mac.begin(), mac.end());
    
    // V = HMAC(Key, V)
    HmacSha256::compute(mac, Key, V);
    V.assign(mac.begin(), mac.end());
    
    if (data1.empty() && data2.empty() && data3.empty()) {
        return;
    }
    
    // Key = HMAC(Key, V || 0x01 || provided_data)
    input.clear();
    input.insert(input.end(), V.begin(), V.end());
    input.push_back(0x01);
    if (!data1.empty()) input.insert(input.end(), data1.begin(), data1.end());
    if (!data2.empty()) input.insert(input.end(), data2.begin(), data2.end());
    if (!data3.empty()) input.insert(input.end(), data3.begin(), data3.end());
    
    HmacSha256::compute(mac, Key, input);
    Key.assign(mac.begin(), mac.end());
    
    // V = HMAC(Key, V)
    HmacSha256::compute(mac, Key, V);
    V.assign(mac.begin(), mac.end());

    std::memset(mac.data(), 0, mac.size());
    std::memset(input.data(), 0, input.size());
}

void HmacDrbg::instantiate(
    std::span<const uint8_t> entropy,
    std::span<const uint8_t> nonce,
    std::span<const uint8_t> personalization_string) noexcept 
{
    Key.assign(HmacSha256::MAC_SIZE, 0x00);
    V.assign(HmacSha256::MAC_SIZE, 0x01);
    
    update_multiple(entropy, nonce, personalization_string);
    reseed_counter = 1;
}

void HmacDrbg::reseed(
    std::span<const uint8_t> entropy,
    std::span<const uint8_t> additional_input) noexcept 
{
    update_multiple(entropy, additional_input, {});
    reseed_counter = 1;
}

bool HmacDrbg::generate(
    std::span<uint8_t> out,
    std::span<const uint8_t> additional_input) noexcept 
{
    if (reseed_counter > RESEED_INTERVAL) {
        return false; // Require reseed
    }
    
    if (!additional_input.empty()) {
        update(additional_input);
    }
    
    size_t generated = 0;
    std::array<uint8_t, HmacSha256::MAC_SIZE> mac;
    
    while (generated < out.size()) {
        HmacSha256::compute(mac, Key, V);
        V.assign(mac.begin(), mac.end());
        
        size_t to_copy = std::min(static_cast<size_t>(HmacSha256::MAC_SIZE), out.size() - generated);
        std::memcpy(out.data() + generated, V.data(), to_copy);
        generated += to_copy;
    }
    
    update(additional_input);
    reseed_counter++;
    
    std::memset(mac.data(), 0, mac.size());
    return true;
}

} // namespace nit::crypto::osnova
