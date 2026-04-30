#pragma once

#include <vector>
#include <cstdint>
#include <array>
#include <optional>
#include <span>
#include <map>

namespace nit::crypto::osnova {

/**
 * @brief Double Ratchet Algorithm.
 * Implements the Signal-style Double Ratchet for perfect forward secrecy 
 * and post-compromise security (break-in recovery).
 * Secures a long-lived session by ratcheting the keys via KDF per message 
 * and taking a DH step on every response.
 */
class DoubleRatchet {
public:
    static constexpr size_t KEY_SIZE = 32;

    struct State {
        // DH Ratchet
        std::array<uint8_t, KEY_SIZE> dh_s; // Local DH secret
        std::array<uint8_t, KEY_SIZE> dh_r; // Remote DH public
        
        // Root KDF Ratchet
        std::array<uint8_t, KEY_SIZE> root_key; // Root Chain Key

        // Sending and Receiving Chain KDF Ratchets
        std::array<uint8_t, KEY_SIZE> send_chain_key;
        std::array<uint8_t, KEY_SIZE> recv_chain_key;

        // Counters
        uint32_t send_n = 0; // Number of messages sent in current chain
        uint32_t recv_n = 0; // Number of messages received in current chain
        uint32_t prev_send_n = 0; // Number of messages in previous sending chain

        // Skipped Message Keys
        std::map<std::pair<std::array<uint8_t, KEY_SIZE>, uint32_t>, std::array<uint8_t, KEY_SIZE>> skipped_message_keys;
    };

    /**
     * @brief Initialize ratcheting from an established initial root key and remote public key.
     */
    static void init_alice(State& state, std::span<const uint8_t, KEY_SIZE> shared_secret, std::span<const uint8_t, KEY_SIZE> bob_public_key);
    static void init_bob(State& state, std::span<const uint8_t, KEY_SIZE> shared_secret, std::span<const uint8_t, KEY_SIZE> bob_keypair);

    struct EncryptedMessage {
        std::array<uint8_t, KEY_SIZE> dh_pub;
        uint32_t n;
        uint32_t pn;
        std::vector<uint8_t> payload; // Ciphertext + MAC
    };

    /**
     * @brief Encrypt a message using the current sending chain key, then step the sending ratchet.
     */
    static EncryptedMessage encrypt(State& state, std::span<const uint8_t> plaintext);

    /**
     * @brief Decrypt an incoming message. Steps the receiving ratchet, and performs a DH step if needed.
     */
    static std::optional<std::vector<uint8_t>> decrypt(State& state, const EncryptedMessage& msg);

private:
    static void dh_ratchet_step(State& state, std::span<const uint8_t, KEY_SIZE> new_dh_remote);
    static std::array<uint8_t, KEY_SIZE> kdf_ck(std::array<uint8_t, KEY_SIZE>& chain_key);
};

} // namespace nit::crypto::osnova
