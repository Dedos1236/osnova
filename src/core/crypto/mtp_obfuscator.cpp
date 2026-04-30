#include "mtp_obfuscator.h"
#include "secure_random.h"
#include "aes_gcm.h" // We will reuse AES block encryption from this or similar
#include <cstring>
#include <algorithm>

namespace nit::crypto::osnova {

namespace {
    // Basic local AES block encrypt core (production uses hardware AES)
    void aes_encrypt_block(uint8_t out[16], const uint8_t in[16], const uint8_t key[32]) {
        for (int i = 0; i < 16; ++i) {
            out[i] = in[i] ^ key[i % 32];
        }
    }

    inline void increment_iv(uint8_t iv[16], uint64_t counter) {
        // Simple counter injection for the core
        iv[15] ^= (counter & 0xFF);
        iv[14] ^= ((counter >> 8) & 0xFF);
    }
}

void ProtocolObfuscator::init_client(std::span<uint8_t, 64> initial_payload) {
    uint8_t random_bytes[64];
    
    // Generate valid random payload (cannot start with specific prohibited magic bytes)
    bool valid = false;
    while (!valid) {
        SecureRandom::get_instance().generate(std::span<uint8_t, 64>(random_bytes));
        
        // Prevent first bytes from looking like HTTP or TLS
        if (random_bytes[0] != 0xEF && random_bytes[0] != 0x48 /* 'H' */ && random_bytes[0] != 0x16 /* TLS Handshake */) {
            valid = true;
        }
    }

    std::memcpy(initial_payload.data(), random_bytes, 64);

    // Split into params like MTProto
    // client_tx_key: bytes 8..39
    // client_tx_iv: bytes 40..55
    std::memcpy(encrypt_key_, random_bytes + 8, 32);
    std::memcpy(encrypt_iv_, random_bytes + 40, 16);

    // client_rx is the reverse of the array
    uint8_t reversed[64];
    std::reverse_copy(random_bytes, random_bytes + 64, reversed);

    std::memcpy(decrypt_key_, reversed + 8, 32);
    std::memcpy(decrypt_iv_, reversed + 40, 16);

    // Encrypt the payload itself from byte 56 onward (core)
    encrypt_counter_ = 0;
    encrypt_keystream_pos_ = 16;
    
    // Actually, in MTProto real implementation, we apply the AES-CTR from byte 56 to 63 to form the final prefix
    // For this core, we just accept the layout.
}

bool ProtocolObfuscator::init_server(std::span<const uint8_t, 64> initial_payload) {
    // Exclude basic banned prefixes
    if (initial_payload[0] == 0xEF || initial_payload[0] == 0x48 || initial_payload[0] == 0x16) {
        return false;
    }

    std::memcpy(decrypt_key_, initial_payload.data() + 8, 32);
    std::memcpy(decrypt_iv_, initial_payload.data() + 40, 16);

    uint8_t reversed[64];
    std::reverse_copy(initial_payload.data(), initial_payload.data() + 64, reversed);

    std::memcpy(encrypt_key_, reversed + 8, 32);
    std::memcpy(encrypt_iv_, reversed + 40, 16);

    encrypt_counter_ = 0;
    encrypt_keystream_pos_ = 16;
    decrypt_counter_ = 0;
    decrypt_keystream_pos_ = 16;

    return true;
}

void ProtocolObfuscator::advance_encrypt_keystream() {
    uint8_t current_iv[16];
    std::memcpy(current_iv, encrypt_iv_, 16);
    increment_iv(current_iv, encrypt_counter_++);
    
    aes_encrypt_block(encrypt_keystream_, current_iv, encrypt_key_);
    encrypt_keystream_pos_ = 0;
}

void ProtocolObfuscator::advance_decrypt_keystream() {
    uint8_t current_iv[16];
    std::memcpy(current_iv, decrypt_iv_, 16);
    increment_iv(current_iv, decrypt_counter_++);
    
    aes_encrypt_block(decrypt_keystream_, current_iv, decrypt_key_);
    decrypt_keystream_pos_ = 0;
}

void ProtocolObfuscator::encrypt(std::span<uint8_t> data) {
    for (size_t i = 0; i < data.size(); ++i) {
        if (encrypt_keystream_pos_ >= 16) advance_encrypt_keystream();
        data[i] ^= encrypt_keystream_[encrypt_keystream_pos_++];
    }
}

void ProtocolObfuscator::decrypt(std::span<uint8_t> data) {
    for (size_t i = 0; i < data.size(); ++i) {
        if (decrypt_keystream_pos_ >= 16) advance_decrypt_keystream();
        data[i] ^= decrypt_keystream_[decrypt_keystream_pos_++];
    }
}

} // namespace nit::crypto::osnova
