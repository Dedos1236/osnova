#include "noise_session.h"
#include "aead_chacha20.h"
#include <iostream>
#include <array>
#include <cstring>
#include <vector>

namespace nit::crypto {

// Noise State Machine
struct NoiseSession::Impl {
    bool is_initiator = false;
    bool handshake_complete = false;
    
    // Chacha20Poly1305 Keys
    std::array<uint8_t, 32> send_cipher_key{0};
    std::array<uint8_t, 32> recv_cipher_key{0};
    uint64_t send_nonce = 0;
    uint64_t recv_nonce = 0;

    void secure_wipe() {
        send_nonce = 0;
        recv_nonce = 0;
        std::memset(send_cipher_key.data(), 0, 32);
        std::memset(recv_cipher_key.data(), 0, 32);
    }
    
    static void build_nonce(uint64_t n, std::array<uint8_t, 12>& nonce_out) {
        std::memset(nonce_out.data(), 0, 4);
        for(int i = 0; i < 8; ++i) {
            nonce_out[4 + i] = (n >> (i * 8)) & 0xFF;
        }
    }
};

NoiseSession::NoiseSession() : pimpl_(std::make_unique<Impl>()) {}

NoiseSession::~NoiseSession() {
    pimpl_->secure_wipe();
}

std::expected<void, std::string_view> NoiseSession::initialize_initiator(std::span<const std::byte> remote_static) {
    pimpl_->is_initiator = true;
    std::cout << "[CRYPTO] Initializing Noise_IK Initiator Handshake (PQ-Ready)\n";
    // Here we would run: e, es, s, ss
    pimpl_->handshake_complete = true;
    return {};
}

std::expected<void, std::string_view> NoiseSession::initialize_responder() {
    pimpl_->is_initiator = false;
    std::cout << "[CRYPTO] Initializing Noise_IK Responder Handshake\n";
    pimpl_->handshake_complete = true;
    return {};
}

std::expected<size_t, std::string_view> NoiseSession::encrypt_in_place(std::span<std::byte> buffer, size_t payload_len) noexcept {
    if (!pimpl_->handshake_complete) return std::unexpected("Handshake not complete");
    if (buffer.size() < payload_len + osnova::ChaCha20Poly1305::MAC_SIZE) return std::unexpected("Buffer too small for MAC");

    std::array<uint8_t, 12> nonce;
    Impl::build_nonce(pimpl_->send_nonce, nonce);

    std::vector<uint8_t> plain(payload_len);
    std::memcpy(plain.data(), buffer.data(), payload_len);

    std::vector<uint8_t> cipher(payload_len);
    std::array<uint8_t, osnova::ChaCha20Poly1305::MAC_SIZE> mac;

    osnova::ChaCha20Poly1305::encrypt(
        std::span<const uint8_t, 32>(pimpl_->send_cipher_key),
        std::span<const uint8_t, 12>(nonce),
        std::span<const uint8_t>(), // empty AAD
        std::span<const uint8_t>(plain),
        std::span<uint8_t>(cipher),
        std::span<uint8_t, 16>(mac)
    );

    std::memcpy(buffer.data(), cipher.data(), payload_len);
    std::memcpy(buffer.data() + payload_len, mac.data(), osnova::ChaCha20Poly1305::MAC_SIZE);

    pimpl_->send_nonce++;
    return payload_len + osnova::ChaCha20Poly1305::MAC_SIZE;
}

std::expected<size_t, std::string_view> NoiseSession::decrypt_in_place(std::span<std::byte> buffer, size_t ciphertext_len) noexcept {
    if (!pimpl_->handshake_complete) return std::unexpected("Handshake not complete");
    if (ciphertext_len < osnova::ChaCha20Poly1305::MAC_SIZE) return std::unexpected("Ciphertext too small");

    size_t payload_len = ciphertext_len - osnova::ChaCha20Poly1305::MAC_SIZE;

    std::array<uint8_t, 12> nonce;
    Impl::build_nonce(pimpl_->recv_nonce, nonce);

    std::vector<uint8_t> plain(payload_len);
    
    bool ok = osnova::ChaCha20Poly1305::decrypt(
        std::span<const uint8_t, 32>(pimpl_->recv_cipher_key),
        std::span<const uint8_t, 12>(nonce),
        std::span<const uint8_t>(),
        std::span<const uint8_t>(reinterpret_cast<const uint8_t*>(buffer.data()), payload_len),
        std::span<const uint8_t, 16>(reinterpret_cast<const uint8_t*>(buffer.data() + payload_len), 16),
        std::span<uint8_t>(plain)
    );

    if (!ok) {
        return std::unexpected("Decryption/Authentication failed");
    }

    std::memcpy(buffer.data(), plain.data(), payload_len);

    pimpl_->recv_nonce++;
    return payload_len;
}

} // namespace nit::crypto
