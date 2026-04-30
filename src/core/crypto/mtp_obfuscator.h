#pragma once

#include <cstdint>
#include <span>
#include <vector>

namespace nit::crypto::osnova {

/**
 * @brief Zero-RTT Protocol Obfuscation (similar to MTProto intermediate obfuscation).
 * Hides handshake signatures to prevent Deep Packet Inspection (DPI).
 * Uses AES-CTR derived from random initial bytes.
 */
class ProtocolObfuscator {
public:
    static constexpr size_t OBFUSCATION_HEADER_SIZE = 64;

    ProtocolObfuscator() = default;

    /**
     * @brief Initialize as client. Sets up encryption/decryption state and generates the prefix.
     * 
     * @param initial_payload Random 64-byte payload generated to exchange.
     */
    void init_client(std::span<uint8_t, 64> initial_payload);

    /**
     * @brief Initialize as server. Reads the client's 64-byte payload.
     * 
     * @param initial_payload The received 64 bytes.
     * @return true if payload is structurally valid.
     */
    bool init_server(std::span<const uint8_t, 64> initial_payload);

    /**
     * @brief Encrypt data in-place using the transmit state.
     */
    void encrypt(std::span<uint8_t> data);

    /**
     * @brief Decrypt data in-place using the receive state.
     */
    void decrypt(std::span<uint8_t> data);

private:
    uint8_t encrypt_key_[32];
    uint8_t encrypt_iv_[16];
    uint8_t decrypt_key_[32];
    uint8_t decrypt_iv_[16];
    
    // CTR state
    uint64_t encrypt_counter_ = 0;
    uint8_t encrypt_keystream_[16] = {0};
    size_t encrypt_keystream_pos_ = 16;

    uint64_t decrypt_counter_ = 0;
    uint8_t decrypt_keystream_[16] = {0};
    size_t decrypt_keystream_pos_ = 16;

    void advance_encrypt_keystream();
    void advance_decrypt_keystream();
};

} // namespace nit::crypto::osnova
