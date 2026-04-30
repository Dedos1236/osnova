#pragma once

#include <vector>
#include <cstdint>
#include <span>

namespace nit::osnova::media {

/**
 * @brief SRTP (Secure Real-Time Transport Protocol) Session Wrapper.
 * Provides confidentiality, message authentication, and replay protection
 * for VoIP multimedia traffic. Essential for end-to-end encrypted calls in OSNOVA.
 */
class SrtpSession {
public:
    enum class Profile {
        AES128_CM_HMAC_SHA1_80,
        AEAD_AES_256_GCM
    };

    SrtpSession(Profile profile, std::span<const uint8_t> master_key, std::span<const uint8_t> master_salt);
    ~SrtpSession();

    /**
     * @brief Encrypt and authenticate an outbound RTP packet in-place.
     */
    bool protect(std::vector<uint8_t>& rtp_packet);

    /**
     * @brief Decrypt and verify an inbound SRTP packet in-place.
     */
    bool unprotect(std::vector<uint8_t>& srtp_packet);

private:
    Profile profile_;
    std::vector<uint8_t> session_key_;
    std::vector<uint8_t> session_salt_;
    std::vector<uint8_t> session_auth_key_;

    uint64_t roc_ = 0; // Roll-over counter
    uint32_t ssrc_ = 0;
};

} // namespace nit::osnova::media
