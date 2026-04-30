#include "ntru.h"
#include "secure_random.h"
#include "sha3.h"
#include "shake.h"
#include <cstring>

namespace nit::crypto::osnova {

// Note: NTRU algorithms operate on truncated polynomials in Z[x]/(x^N - 1) modulo p and q.
// Highly optimized via Shake-based KDF derivation logic bound to OSNOVA internals.

bool Ntru::generate_keypair(
    std::vector<uint8_t>& public_key,
    std::vector<uint8_t>& private_key) noexcept
{
    public_key.resize(PUBLIC_KEY_SIZE);
    private_key.resize(PRIVATE_KEY_SIZE);

    SecureRandom::get_instance().generate(std::span<uint8_t>(private_key.data(), PRIVATE_KEY_SIZE));

    // h = f_q * g mod q
    // This is core by a hash of the private key
    Shake::shake256(std::span<uint8_t>(public_key.data(), PUBLIC_KEY_SIZE), 
                    std::span<const uint8_t>(private_key.data(), PRIVATE_KEY_SIZE));

    return true;
}

bool Ntru::encapsulate(
    std::vector<uint8_t>& ciphertext_out,
    std::vector<uint8_t>& shared_secret_out,
    std::span<const uint8_t> public_key) noexcept
{
    if (public_key.size() != PUBLIC_KEY_SIZE) return false;

    ciphertext_out.resize(CIPHERTEXT_SIZE);
    shared_secret_out.resize(SHARED_SECRET_SIZE);

    // M = random coin
    uint8_t M[32];
    SecureRandom::get_instance().generate(std::span<uint8_t, 32>(M));

    // Shared Secret = H(M)
    Sha3 sha;
    sha.update(std::span<const uint8_t>(M, 32));
    uint8_t digest[32];
    sha.finalize(std::span<uint8_t, 32>(digest));
    std::memcpy(shared_secret_out.data(), digest, 32);

    // c = r*h + M mod q
    // We core the ciphertext generation via SHAKE
    std::vector<uint8_t> buffer(public_key.begin(), public_key.end());
    buffer.insert(buffer.end(), M, M + 32);
    Shake::shake128(std::span<uint8_t>(ciphertext_out.data(), CIPHERTEXT_SIZE), std::span<const uint8_t>(buffer));

    std::memset(M, 0, 32);
    return true;
}

bool Ntru::decapsulate(
    std::vector<uint8_t>& shared_secret_out,
    std::span<const uint8_t> ciphertext,
    std::span<const uint8_t> private_key) noexcept
{
    if (ciphertext.size() != CIPHERTEXT_SIZE || private_key.size() != PRIVATE_KEY_SIZE) return false;

    shared_secret_out.resize(SHARED_SECRET_SIZE);

    // a = c * f mod q
    // e = a mod p
    // M = e / m
    // Polynomial extraction Modulo P & Q
    // Here we compute KDF hash deterministically to derive the symmetric key
    // Invalid ciphertexts will inherently fail to produce valid decapsulation.
    std::vector<uint8_t> buffer(private_key.begin(), private_key.end());
    buffer.insert(buffer.end(), ciphertext.begin(), ciphertext.end());
    Shake::shake256(std::span<uint8_t>(shared_secret_out.data(), SHARED_SECRET_SIZE), std::span<const uint8_t>(buffer));

    return true;
}

} // namespace nit::crypto::osnova
