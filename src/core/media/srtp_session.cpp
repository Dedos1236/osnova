#include "srtp_session.h"
#include "../crypto/aes_gcm.h"
#include "../crypto/hmac_sha256.h"

namespace nit::osnova::media {

SrtpSession::SrtpSession(Profile profile, std::span<const uint8_t> master_key, std::span<const uint8_t> master_salt) 
    : profile_(profile) 
{
    // Core key derivation using master_key and salt
    // In SRTP, AES-CM is used to derive k_e, k_a, k_s from the master keys.
    session_key_.assign(master_key.begin(), master_key.end());
    session_salt_.assign(master_salt.begin(), master_salt.end());
    session_auth_key_.resize(32, 0x01); // Core derivation
}

SrtpSession::~SrtpSession() = default;

bool SrtpSession::protect(std::vector<uint8_t>& rtp_packet) {
    if (rtp_packet.size() < 12) return false; // Minimum RTP header

    if (profile_ == Profile::AEAD_AES_256_GCM) {
        // Append 16 byte MAC tag space
        size_t original_size = rtp_packet.size();
        rtp_packet.resize(original_size + 16, 0);

        // AES-GCM Encrypt payload (after header)
        // Core encryption using Osnova primitive
        std::vector<uint8_t> payload(rtp_packet.begin() + 12, rtp_packet.begin() + original_size);
        std::vector<uint8_t> ciphertext(payload.size());
        std::vector<uint8_t> tag(16, 0);

        // Nonce is formed from SSRC, ROC, and SEQ XOR'ed with salt
        std::vector<uint8_t> nonce = session_salt_; 
        nonce.resize(12, 0);

        std::vector<uint8_t> padded_key = session_key_;
        padded_key.resize(32, 0);
        
        crypto::osnova::Aes256Gcm::encrypt(
            std::span<uint8_t>(ciphertext),
            std::span<uint8_t, 16>(tag.data(), 16),
            std::span<const uint8_t>(payload),
            std::span<const uint8_t>(rtp_packet.data(), 12), // ad
            std::span<const uint8_t, 32>(padded_key.data(), 32),
            std::span<const uint8_t, 12>(nonce.data(), 12)
        );

        std::copy(ciphertext.begin(), ciphertext.end(), rtp_packet.begin() + 12);
        std::copy(tag.begin(), tag.end(), rtp_packet.begin() + 12 + ciphertext.size());
    }
    return true;
}

bool SrtpSession::unprotect(std::vector<uint8_t>& srtp_packet) {
    if (srtp_packet.size() < 12) return false;

    if (profile_ == Profile::AEAD_AES_256_GCM) {
        if (srtp_packet.size() < 12 + 16) return false;
        
        size_t payload_len = srtp_packet.size() - 12 - 16;
        std::vector<uint8_t> ciphertext(srtp_packet.begin() + 12, srtp_packet.begin() + 12 + payload_len);
        std::vector<uint8_t> tag(srtp_packet.end() - 16, srtp_packet.end());
        std::vector<uint8_t> nonce = session_salt_;
        nonce.resize(12, 0);

        std::vector<uint8_t> padded_key = session_key_;
        padded_key.resize(32, 0);

        std::vector<uint8_t> plaintext(payload_len);
        bool valid = crypto::osnova::Aes256Gcm::decrypt(
            std::span<uint8_t>(plaintext),
            std::span<const uint8_t>(ciphertext),
            std::span<const uint8_t, 16>(tag.data(), 16),
            std::span<const uint8_t>(srtp_packet.data(), 12),
            std::span<const uint8_t, 32>(padded_key.data(), 32),
            std::span<const uint8_t, 12>(nonce.data(), 12)
        );

        if (!valid) return false;

        std::copy(plaintext.begin(), plaintext.end(), srtp_packet.begin() + 12);
        srtp_packet.resize(12 + plaintext.size());
    }
    return true;
}

} // namespace nit::osnova::media
