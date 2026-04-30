#pragma once

#include <vector>
#include <cstdint>
#include <span>

namespace nit::osnova::media {

/**
 * @brief AV1 Bitstream Parser / Depacketizer.
 * Processes high-efficiency AV1 video streams (AOMedia Video 1).
 * AV1 provides 30% better compression than HEVC/H.265, making it the supreme 
 * choice for OSNOVA's seamless 4k group video calls with minimal bandwidth.
 */
class Av1Parser {
public:
    enum class OBU_Type {
        SEQUENCE_HEADER = 1,
        TEMPORAL_DELIMITER = 2,
        FRAME_HEADER = 3,
        TILE_GROUP = 4,
        METADATA = 5,
        FRAME = 6,
        REDUNDANT_FRAME_HEADER = 7,
        PADDING = 15,
        UNKNOWN = 99
    };

    struct OBU {
        OBU_Type type;
        bool has_size_field;
        bool has_extension;
        uint8_t temporal_id{0};
        uint8_t spatial_id{0};
        size_t size;
        std::vector<uint8_t> payload;
    };

    /**
     * @brief Parses an aggregated raw AV1 bitstream chunk into multiple Open Bitstream Units (OBUs).
     */
    static std::vector<OBU> parse_bitstream(std::span<const uint8_t> data);

    /**
     * @brief Packetizes OBUs into RTP packets following RFC 8986 (AV1 RTP payload format).
     * Necessary for low-latency transmission.
     */
    static std::vector<std::vector<uint8_t>> packetize_for_rtp(const std::vector<OBU>& obus, size_t mtu = 1200);

private:
    static size_t read_leb128(std::span<const uint8_t> data, size_t offset, uint64_t& out_value);
};

} // namespace nit::osnova::media
