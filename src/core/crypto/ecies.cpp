#include "ecies.h"
#include "curve25519.h"
#include "hkdf_sha256.h"
#include "aes_gcm.h"
#include "secure_random.h"
#include <cstring>

namespace nit::crypto::osnova {

bool Ecies::encrypt(
    std::vector<uint8_t>& ciphertext,
    std::span<const uint8_t, 32> recipient_public_key,
    std::span<const uint8_t> plaintext)
{
    // 1. Generate ephemeral keypair
    std::vector<uint8_t> ephem_priv(32);
    std::vector<uint8_t> ephem_pub(32);
    SecureRandom::get_instance().generate(std::span<uint8_t>(ephem_priv));
    Curve25519::generate_public_key(
        std::span<uint8_t, 32>(ephem_pub.data(), 32),
        std::span<const uint8_t, 32>(ephem_priv.data(), 32)
    );

    // 2. ECDH Shared Secret
    std::vector<uint8_t> shared_secret(32);
    Curve25519::x25519(
        std::span<uint8_t, 32>(shared_secret.data(), 32),
        std::span<const uint8_t, 32>(ephem_priv.data(), 32),
        recipient_public_key);

    // 3. Derive Symmetric Key using HKDF
    std::vector<uint8_t> symmetric_key(32);
    HkdfSha256::expand(
        std::span<uint8_t>(symmetric_key),
        shared_secret,
        std::span<const uint8_t>(reinterpret_cast<const uint8_t*>("OSNOVA_ECIES"), 12)
    );

    // 4. Encrypt with AES-GCM
    std::vector<uint8_t> iv(Aes256Gcm::NONCE_SIZE);
    SecureRandom::get_instance().generate(std::span<uint8_t>(iv));

    std::vector<uint8_t> ctext(plaintext.size());
    std::vector<uint8_t> tag(Aes256Gcm::TAG_SIZE);

    Aes256Gcm::encrypt(
        std::span<uint8_t>(ctext),
        std::span<uint8_t, Aes256Gcm::TAG_SIZE>(tag.data(), Aes256Gcm::TAG_SIZE),
        plaintext,
        std::span<const uint8_t>(), // empty AD
        std::span<const uint8_t, 32>(symmetric_key.data(), 32),
        std::span<const uint8_t, Aes256Gcm::NONCE_SIZE>(iv.data(), Aes256Gcm::NONCE_SIZE));

    // 5. Pack [ephem_pub(32) || iv(12) || ctext || tag(16)]
    ciphertext.clear();
    ciphertext.reserve(32 + Aes256Gcm::NONCE_SIZE + ctext.size() + Aes256Gcm::TAG_SIZE);
    
    ciphertext.insert(ciphertext.end(), ephem_pub.begin(), ephem_pub.end());
    ciphertext.insert(ciphertext.end(), iv.begin(), iv.end());
    ciphertext.insert(ciphertext.end(), ctext.begin(), ctext.end());
    ciphertext.insert(ciphertext.end(), tag.begin(), tag.end());

    return true;
}

bool Ecies::decrypt(
    std::vector<uint8_t>& plaintext,
    std::span<const uint8_t, 32> recipient_private_key,
    std::span<const uint8_t> ciphertext)
{
    const size_t overhead = 32 + Aes256Gcm::NONCE_SIZE + Aes256Gcm::TAG_SIZE;
    if (ciphertext.size() < overhead) return false;

    // 1. Extract components
    std::span<const uint8_t, 32> ephem_pub(ciphertext.data(), 32);
    std::span<const uint8_t, Aes256Gcm::NONCE_SIZE> iv(ciphertext.data() + 32, Aes256Gcm::NONCE_SIZE);
    
    size_t ctext_len = ciphertext.size() - overhead;
    std::span<const uint8_t> ctext(ciphertext.data() + 32 + Aes256Gcm::NONCE_SIZE, ctext_len);
    
    std::span<const uint8_t, Aes256Gcm::TAG_SIZE> tag(ciphertext.data() + 32 + Aes256Gcm::NONCE_SIZE + ctext_len, Aes256Gcm::TAG_SIZE);

    // 2. ECDH Shared Secret
    std::vector<uint8_t> shared_secret(32);
    Curve25519::x25519(
        std::span<uint8_t, 32>(shared_secret.data(), 32),
        recipient_private_key,
        ephem_pub);

    // 3. Derive Symmetric Key
    std::vector<uint8_t> symmetric_key(32);
    HkdfSha256::expand(
        std::span<uint8_t>(symmetric_key),
        shared_secret,
        std::span<const uint8_t>(reinterpret_cast<const uint8_t*>("OSNOVA_ECIES"), 12)
    );

    // 4. Decrypt via AES-GCM
    plaintext.resize(ctext_len);
    if (!Aes256Gcm::decrypt(
        std::span<uint8_t>(plaintext),
        ctext,
        tag,
        std::span<const uint8_t>(),
        std::span<const uint8_t, 32>(symmetric_key.data(), 32),
        iv))
    {
        plaintext.clear();
        return false;
    }

    return true;
}

} // namespace nit::crypto::osnova
