#pragma once

#include <cstdint>
#include <span>
#include <vector>
#include <string>

namespace nit::osnova::media {

/**
 * @brief RTP Packetizer (RFC 3550).
 * Handles building and parsing RTP headers for audio/video streaming in OSNOVA.
 */
class RtpPacketizer {
public:
    static constexpr size_t RTP_HEADER_SIZE = 12;

    struct RtpHeader {
        uint8_t version;
        bool padding;
        bool extension;
        uint8_t csrc_count;
        bool marker;
        uint8_t payload_type;
        uint16_t sequence_number;
        uint32_t timestamp;
        uint32_t ssrc;
        std::vector<uint32_t> csrc_list;
    };

    RtpPacketizer(uint8_t payload_type, uint32_t ssrc);
    ~RtpPacketizer();

    /**
     * @brief Create an RTP packet.
     */
    std::vector<uint8_t> create_packet(
        uint32_t timestamp,
        bool marker,
        std::span<const uint8_t> payload);

    /**
     * @brief Parse an RTP packet.
     */
    static bool parse_packet(
        RtpHeader& header,
        std::vector<uint8_t>& payload,
        std::span<const uint8_t> packet);

private:
    uint8_t payload_type_;
    uint32_t ssrc_;
    uint16_t sequence_number_;
};

} // namespace nit::osnova::media
