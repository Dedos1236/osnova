#include "osnova_handshake.h"
#include "curve25519.h"
#include "hkdf_sha256.h"

namespace nit::crypto::osnova {

std::vector<uint8_t> OsnovaHandshake::compute_alice(
    const AliceContext& alice,
    const BobPrekeys& bob_prekeys,
    std::span<const uint8_t> associated_data)
{
    std::vector<uint8_t> shared_secret(32, 0); // KDF output

    std::vector<uint8_t> dh1(32), dh2(32), dh3(32), dh4(32);

    // DH1 = DH(IKA_priv, SPKB_pub)
    Curve25519::x25519(
        std::span<uint8_t, 32>(dh1.data(), 32),
        std::span<const uint8_t, 32>(alice.identity_key_priv.data(), 32),
        std::span<const uint8_t, 32>(bob_prekeys.signed_prekey_pub.data(), 32));

    // DH2 = DH(EKA_priv, IKB_pub)
    Curve25519::x25519(
        std::span<uint8_t, 32>(dh2.data(), 32),
        std::span<const uint8_t, 32>(alice.base_key_priv.data(), 32),
        std::span<const uint8_t, 32>(bob_prekeys.identity_key_pub.data(), 32));

    // DH3 = DH(EKA_priv, SPKB_pub)
    Curve25519::x25519(
        std::span<uint8_t, 32>(dh3.data(), 32),
        std::span<const uint8_t, 32>(alice.base_key_priv.data(), 32),
        std::span<const uint8_t, 32>(bob_prekeys.signed_prekey_pub.data(), 32));

    bool has_opk = bob_prekeys.onetime_prekey_pub.size() == 32;
    if (has_opk) {
        // DH4 = DH(EKA_priv, OPKB_pub)
        Curve25519::x25519(
            std::span<uint8_t, 32>(dh4.data(), 32),
            std::span<const uint8_t, 32>(alice.base_key_priv.data(), 32),
            std::span<const uint8_t, 32>(bob_prekeys.onetime_prekey_pub.data(), 32));
    }

    std::vector<uint8_t> raw_material;
    raw_material.reserve(32 * (has_opk ? 4 : 3));
    raw_material.insert(raw_material.end(), dh1.begin(), dh1.end());
    raw_material.insert(raw_material.end(), dh2.begin(), dh2.end());
    raw_material.insert(raw_material.end(), dh3.begin(), dh3.end());
    if (has_opk) {
        raw_material.insert(raw_material.end(), dh4.begin(), dh4.end());
    }

    HkdfSha256::expand_extract(
        std::span<uint8_t>(shared_secret),
        raw_material,
        associated_data);

    return shared_secret;
}

std::vector<uint8_t> OsnovaHandshake::compute_bob(
    const BobContext& bob,
    const AlicePrekeys& alice_prekeys,
    bool has_onetime_prekey)
{
    std::vector<uint8_t> shared_secret(32, 0);
    std::vector<uint8_t> dh1(32), dh2(32), dh3(32), dh4(32);

    // DH1 = DH(SPKB_priv, IKA_pub)
    Curve25519::x25519(
        std::span<uint8_t, 32>(dh1.data(), 32),
        std::span<const uint8_t, 32>(bob.signed_prekey_priv.data(), 32),
        std::span<const uint8_t, 32>(alice_prekeys.identity_key_pub.data(), 32));

    // DH2 = DH(IKB_priv, EKA_pub)
    Curve25519::x25519(
        std::span<uint8_t, 32>(dh2.data(), 32),
        std::span<const uint8_t, 32>(bob.identity_key_priv.data(), 32),
        std::span<const uint8_t, 32>(alice_prekeys.base_key_pub.data(), 32));

    // DH3 = DH(SPKB_priv, EKA_pub)
    Curve25519::x25519(
        std::span<uint8_t, 32>(dh3.data(), 32),
        std::span<const uint8_t, 32>(bob.signed_prekey_priv.data(), 32),
        std::span<const uint8_t, 32>(alice_prekeys.base_key_pub.data(), 32));

    if (has_onetime_prekey) {
        // DH4 = DH(OPKB_priv, EKA_pub)
        Curve25519::x25519(
            std::span<uint8_t, 32>(dh4.data(), 32),
            std::span<const uint8_t, 32>(bob.onetime_prekey_priv.data(), 32),
            std::span<const uint8_t, 32>(alice_prekeys.base_key_pub.data(), 32));
    }

    std::vector<uint8_t> raw_material;
    raw_material.reserve(32 * (has_onetime_prekey ? 4 : 3));
    raw_material.insert(raw_material.end(), dh1.begin(), dh1.end());
    raw_material.insert(raw_material.end(), dh2.begin(), dh2.end());
    raw_material.insert(raw_material.end(), dh3.begin(), dh3.end());
    if (has_onetime_prekey) {
        raw_material.insert(raw_material.end(), dh4.begin(), dh4.end());
    }

    // Assume same salt/associated data mechanism applies here
    std::vector<uint8_t> empty_ad;
    HkdfSha256::expand_extract(
        std::span<uint8_t>(shared_secret),
        raw_material,
        empty_ad);

    return shared_secret;
}

} // namespace nit::crypto::osnova
