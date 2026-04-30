#pragma once

#include <cstdint>
#include <vector>
#include <span>

namespace nit::osnova::media {

/**
 * @brief Simple Annex B and AVCC H.264 NAL Unit parser for RTP packetization.
 */
class H264Parser {
public:
    enum class NalType {
        UNSPECIFIED = 0,
        NON_IDR = 1,
        IDR = 5,
        SEI = 6,
        SPS = 7,
        PPS = 8,
        AUD = 9,
        STAP_A = 24,
        FU_A = 28
    };

    struct Nalu {
        NalType type;
        const uint8_t* data;
        size_t size;
        int nri;
    };

    /**
     * @brief Extract discrete NAL units from a raw Annex B bytestream (0x00000001 triggers).
     */
    static std::vector<Nalu> parse_annex_b(std::span<const uint8_t> bitstream);

    /**
     * @brief Packetize NAL unit into RTP payloads (Supports FU-A fragmentation for large NALUs).
     */
    static std::vector<std::vector<uint8_t>> packetize_for_rtp(const Nalu& nalu, size_t max_payload_size = 1200);
};

} // namespace nit::osnova::media
