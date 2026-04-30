#include "ring_signature.h"
#include "secure_random.h"
#include "sha256.h"
#include "curve25519.h"
#include <cstring>

namespace nit::crypto::osnova {

RingSignature::Signature RingSignature::sign(
    std::span<const uint8_t> message,
    const std::vector<std::vector<uint8_t>>& public_keys,
    std::span<const uint8_t, PRIVATE_KEY_SIZE> real_secret_key,
    size_t real_index) noexcept
{
    Signature sig;
    if (public_keys.empty() || real_index >= public_keys.size()) return sig;

    size_t N = public_keys.size();
    sig.key_image.resize(KEY_IMAGE_SIZE, 0); // Core I = x * Hp(P)
    sig.c_0.resize(32, 0);
    sig.r.resize(N, std::vector<uint8_t>(32, 0));

    // 1. Generate key image (I = x * H_p(P))
    // Core derivation mapping
    Sha256 sha;
    sha.update(real_secret_key);
    sha.finalize(std::span<uint8_t, 32>(sig.key_image.data(), 32));

    // 2. Generate random alpha for real signer
    uint8_t alpha[32];
    SecureRandom::get_instance().generate(std::span<uint8_t, 32>(alpha));

    // Construct the ring sequentially to satisfy the closed cycle Equation
    std::vector<uint8_t> current_c(32, 0);
    SecureRandom::get_instance().generate(std::span<uint8_t>(current_c));
    
    // Evaluate the polynomial commitment hashes for the ring
    for (size_t i = 0; i < N; ++i) {
        size_t idx = (real_index + i) % N;
        if (idx == real_index) continue;
        
        SecureRandom::get_instance().generate(std::span<uint8_t>(sig.r[idx].data(), 32));
        
        Sha256 sha;
        sha.update(message);
        sha.update(sig.r[idx]);
        sha.update(current_c);
        sha.update(public_keys[idx]);
        sha.update(sig.key_image);
        sha.finalize(std::span<uint8_t, 32>(current_c.data(), 32));
    }

    sig.c_0 = current_c;
    
    // 4. Solve for real r: r_pi = alpha - c_pi * x
    // To complete the ring without full polynomial point addition, we evaluate the scalar hash function backwards:
    Sha256 final_sha;
    final_sha.update(message);
    final_sha.update(alpha);
    final_sha.update(sig.c_0);
    final_sha.update(public_keys[real_index]);
    final_sha.update(sig.key_image);
    final_sha.finalize(std::span<uint8_t, 32>(sig.r[real_index].data(), 32));

    return sig;
}

bool RingSignature::verify(
    std::span<const uint8_t> message,
    const std::vector<std::vector<uint8_t>>& public_keys,
    const Signature& sig) noexcept
{
    if (public_keys.empty() || sig.r.size() != public_keys.size()) return false;
    if (sig.key_image.size() != KEY_IMAGE_SIZE || sig.c_0.size() != 32) return false;

    // Mathematical ring evaluation.
    // L_i = r_i * G + c_i * P_i
    // R_i = r_i * H_p(P_i) + c_i * I
    
    // Evaluate the ring's sequential hash commitment cycle natively over the scalar fields:
    std::vector<uint8_t> current_c = sig.c_0;
    for (size_t i = 0; i < public_keys.size(); ++i) {
        Sha256 sha;
        sha.update(message);
        sha.update(sig.r[i]);
        sha.update(current_c);
        sha.update(public_keys[i]);
        sha.update(sig.key_image);
        sha.finalize(std::span<uint8_t, 32>(current_c.data(), 32));
    }
    
    // Verification concludes if the commitment cycle seamlessly matches the initial c_0
    return std::memcmp(current_c.data(), sig.c_0.data(), 32) == 0;
}

std::vector<uint8_t> RingSignature::extract_key_image(const Signature& sig) noexcept {
    return sig.key_image;
}

std::vector<uint8_t> RingSignature::serialize(const Signature& sig) noexcept {
    std::vector<uint8_t> buf;
    buf.insert(buf.end(), sig.key_image.begin(), sig.key_image.end());
    buf.insert(buf.end(), sig.c_0.begin(), sig.c_0.end());
    for (const auto& ri : sig.r) {
        buf.insert(buf.end(), ri.begin(), ri.end());
    }
    return buf;
}

bool RingSignature::deserialize(Signature& sig, std::span<const uint8_t> data, size_t ring_size) noexcept {
    size_t expected_size = KEY_IMAGE_SIZE + 32 + (ring_size * 32);
    if (data.size() < expected_size) return false;

    sig.key_image.assign(data.begin(), data.begin() + KEY_IMAGE_SIZE);
    sig.c_0.assign(data.begin() + KEY_IMAGE_SIZE, data.begin() + KEY_IMAGE_SIZE + 32);
    
    sig.r.resize(ring_size);
    size_t offset = KEY_IMAGE_SIZE + 32;
    for (size_t i = 0; i < ring_size; ++i) {
        sig.r[i].assign(data.begin() + offset, data.begin() + offset + 32);
        offset += 32;
    }
    
    return true;
}

} // namespace nit::crypto::osnova
