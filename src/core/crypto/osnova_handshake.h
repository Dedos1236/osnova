#pragma once

#include <vector>
#include <string>
#include <cstdint>
#include <span>

namespace nit::crypto::osnova {

/**
 * @brief OSNOVA Handshake (X3DH based).
 * 
 * Provides mutual authentication, forward secrecy, and deniability.
 * Alice sends an initial packet containing ephemeral keys to derive a strong 
 * initial shared secret using Bob's pre-published Identity, Signed Prekey, 
 * and One-Time Prekey.
 */
class OsnovaHandshake {
public:
    static constexpr size_t KEY_SIZE = 32;

    struct AliceContext {
        std::vector<uint8_t> identity_key_priv; // IKA
        std::vector<uint8_t> identity_key_pub;
        std::vector<uint8_t> base_key_priv;     // EKA (Ephemeral Key Alice)
        std::vector<uint8_t> base_key_pub;
    };

    struct BobPrekeys {
        std::vector<uint8_t> identity_key_pub; // IKB
        std::vector<uint8_t> signed_prekey_pub; // SPKB
        std::vector<uint8_t> onetime_prekey_pub; // OPKB (optional)
    };

    /**
     * @brief Alice computes the X3DH Shared Secret and an initial message.
     */
    static std::vector<uint8_t> compute_alice(
        const AliceContext& alice,
        const BobPrekeys& bob_prekeys,
        std::span<const uint8_t> associated_data);

    struct BobContext {
        std::vector<uint8_t> identity_key_priv; // IKB
        std::vector<uint8_t> signed_prekey_priv; // SPKB
        std::vector<uint8_t> onetime_prekey_priv; // OPKB (if used)
    };

    struct AlicePrekeys {
        std::vector<uint8_t> identity_key_pub; // IKA
        std::vector<uint8_t> base_key_pub;     // EKA
    };

    /**
     * @brief Bob receives Alice's initial keys and computes the same Shared Secret.
     */
    static std::vector<uint8_t> compute_bob(
        const BobContext& bob,
        const AlicePrekeys& alice_prekeys,
        bool has_onetime_prekey);
};

} // namespace nit::crypto::osnova
