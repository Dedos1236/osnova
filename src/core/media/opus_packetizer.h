#pragma once

#include <vector>
#include <cstdint>
#include <span>

namespace nit::osnova::media {

/**
 * @brief Opus Audio Packetizer (RFC 7587).
 * Wraps Opus encoded frames into RTP packets for real-time transmission.
 * Supports DTX (Discontinuous Transmission), FEC, and variable bitrates seamlessly.
 */
class OpusPacketizer {
public:
    OpusPacketizer(uint32_t ssrc, uint16_t initial_seq_num, uint32_t payload_type = 111);
    ~OpusPacketizer();

    struct RtpPacket {
        std::vector<uint8_t> data;
        uint16_t sequence_number;
        uint32_t timestamp;
    };

    /**
     * @brief Packetize an Opus frame into an RTP packet.
     * @param opus_frame Raw Opus encoded data.
     * @param frame_duration_ms Normally 2.5, 5, 10, 20, 40, or 60ms.
     * @param marker_bit True if this is the start of a talk spurt (DTX).
     */
    RtpPacket packetize(std::span<const uint8_t> opus_frame, uint32_t frame_duration_ms, bool marker_bit = false);

private:
    uint32_t ssrc_;
    uint16_t current_seq_;
    uint32_t current_timestamp_;
    uint32_t payload_type_;
    
    // Opus is ALWAYS 48000 Hz RTP clock rate, even if internal sample rate is lower
    static constexpr uint32_t CLOCK_RATE = 48000;
};

} // namespace nit::osnova::media
