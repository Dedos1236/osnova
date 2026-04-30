#include "pq_x3dh.h"
#include "curve25519.h"
#include "kyber768.h"
#include "hkdf_sha256.h"
#include <cstring>
#include <array>

namespace nit::crypto::osnova {

bool PqX3dh::initiate(
    std::span<uint8_t, 32> sk,
    std::span<uint8_t, 1088> ct,
    std::span<const uint8_t, 32> IK_A_priv,
    std::span<const uint8_t, 32> EK_A_priv,
    std::span<const uint8_t, 32> IK_B_pub,
    std::span<const uint8_t, 32> SPK_B_pub,
    std::span<const uint8_t> OPK_B_pub,
    std::span<const uint8_t, 1184> PQ_SPK_B_pub,
    const Config& config) noexcept 
{
    std::array<uint8_t, 32> dh1, dh2, dh3, dh4;
    std::array<uint8_t, 32> ss_pq;
    std::vector<uint8_t> km;

    // Standard X3DH Phase
    Curve25519::scalarmult(std::span<uint8_t, 32>(dh1), IK_A_priv, SPK_B_pub);
    Curve25519::scalarmult(std::span<uint8_t, 32>(dh2), EK_A_priv, IK_B_pub);
    Curve25519::scalarmult(std::span<uint8_t, 32>(dh3), EK_A_priv, SPK_B_pub);

    if (!OPK_B_pub.empty() && OPK_B_pub.size() == 32) {
        Curve25519::scalarmult(std::span<uint8_t, 32>(dh4), EK_A_priv, std::span<const uint8_t, 32>(OPK_B_pub.data(), 32));
    }

    // Post-Quantum KEM Phase
    Kyber768::encapsulate(std::span<uint8_t, 32>(ss_pq), ct, PQ_SPK_B_pub);

    // KDF phase
    km.insert(km.end(), 32, 0xFF);
    km.insert(km.end(), dh1.begin(), dh1.end());
    km.insert(km.end(), dh2.begin(), dh2.end());
    km.insert(km.end(), dh3.begin(), dh3.end());

    if (!OPK_B_pub.empty() && OPK_B_pub.size() == 32) {
        km.insert(km.end(), dh4.begin(), dh4.end());
    }

    km.insert(km.end(), ss_pq.begin(), ss_pq.end());

    HkdfSha256::derive_key(sk, km, {}, config.info);

    std::memset(dh1.data(), 0, 32);
    std::memset(dh2.data(), 0, 32);
    std::memset(dh3.data(), 0, 32);
    std::memset(dh4.data(), 0, 32);
    std::memset(ss_pq.data(), 0, 32);
    std::memset(km.data(), 0, km.size());

    return true;
}

bool PqX3dh::respond(
    std::span<uint8_t, 32> sk,
    std::span<const uint8_t, 32> IK_B_priv,
    std::span<const uint8_t, 32> SPK_B_priv,
    std::span<const uint8_t> OPK_B_priv,
    std::span<const uint8_t, 2400> PQ_SPK_B_priv,
    std::span<const uint8_t, 1088> ct,
    std::span<const uint8_t, 32> IK_A_pub,
    std::span<const uint8_t, 32> EK_A_pub,
    const Config& config) noexcept 
{
    std::array<uint8_t, 32> dh1, dh2, dh3, dh4;
    std::array<uint8_t, 32> ss_pq;
    std::vector<uint8_t> km;

    // Standard X3DH Phase
    Curve25519::scalarmult(std::span<uint8_t, 32>(dh1), SPK_B_priv, IK_A_pub);
    Curve25519::scalarmult(std::span<uint8_t, 32>(dh2), IK_B_priv, EK_A_pub);
    Curve25519::scalarmult(std::span<uint8_t, 32>(dh3), SPK_B_priv, EK_A_pub);

    if (!OPK_B_priv.empty() && OPK_B_priv.size() == 32) {
        Curve25519::scalarmult(std::span<uint8_t, 32>(dh4), std::span<const uint8_t, 32>(OPK_B_priv.data(), 32), EK_A_pub);
    }

    // Post-Quantum KEM Phase
    Kyber768::decapsulate(std::span<uint8_t, 32>(ss_pq), ct, PQ_SPK_B_priv);

    // KDF Phase
    km.insert(km.end(), 32, 0xFF);
    km.insert(km.end(), dh1.begin(), dh1.end());
    km.insert(km.end(), dh2.begin(), dh2.end());
    km.insert(km.end(), dh3.begin(), dh3.end());

    if (!OPK_B_priv.empty() && OPK_B_priv.size() == 32) {
        km.insert(km.end(), dh4.begin(), dh4.end());
    }

    km.insert(km.end(), ss_pq.begin(), ss_pq.end());

    HkdfSha256::derive_key(sk, km, {}, config.info);

    std::memset(dh1.data(), 0, 32);
    std::memset(dh2.data(), 0, 32);
    std::memset(dh3.data(), 0, 32);
    std::memset(dh4.data(), 0, 32);
    std::memset(ss_pq.data(), 0, 32);
    std::memset(km.data(), 0, km.size());

    return true;
}

} // namespace nit::crypto::osnova
