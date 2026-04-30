#include "h264_parser.h"

namespace nit::osnova::media {

std::vector<H264Parser::Nalu> H264Parser::parse_annex_b(std::span<const uint8_t> bitstream) {
    std::vector<Nalu> nalus;
    if (bitstream.size() < 4) return nalus;

    size_t i = 0;
    while (i < bitstream.size() - 3) {
        // Find start code 0x00 0x00 0x00 0x01 or 0x00 0x00 0x01
        size_t start_code_len = 0;
        if (bitstream[i] == 0 && bitstream[i+1] == 0) {
            if (bitstream[i+2] == 1) {
                start_code_len = 3;
            } else if (bitstream[i+2] == 0 && bitstream[i+3] == 1) {
                start_code_len = 4;
            }
        }

        if (start_code_len > 0) {
            size_t nalu_start = i + start_code_len;
            size_t nalu_end = nalu_start;
            
            // Find next start code
            bool found_next = false;
            while (nalu_end < bitstream.size() - 2) {
                if (bitstream[nalu_end] == 0 && bitstream[nalu_end+1] == 0 && 
                    (bitstream[nalu_end+2] == 1 || (nalu_end < bitstream.size()-3 && bitstream[nalu_end+2] == 0 && bitstream[nalu_end+3] == 1))) {
                    found_next = true;
                    break;
                }
                nalu_end++;
            }
            if (!found_next) {
                nalu_end = bitstream.size(); // end of stream
            }

            if (nalu_end > nalu_start) {
                Nalu nalu;
                nalu.data = bitstream.data() + nalu_start;
                nalu.size = nalu_end - nalu_start;
                
                uint8_t header = nalu.data[0];
                nalu.nri = (header >> 5) & 0x03;
                nalu.type = static_cast<NalType>(header & 0x1F);
                
                nalus.push_back(nalu);
            }
            i = nalu_end;
        } else {
            i++;
        }
    }

    return nalus;
}

std::vector<std::vector<uint8_t>> H264Parser::packetize_for_rtp(const Nalu& nalu, size_t max_payload_size) {
    std::vector<std::vector<uint8_t>> packets;

    if (nalu.size <= max_payload_size) {
        // Single NAL unit packet
        std::vector<uint8_t> pkt(nalu.data, nalu.data + nalu.size);
        packets.push_back(pkt);
    } else {
        // Fragmentation Unit (FU-A)
        uint8_t header = nalu.data[0];
        uint8_t nri = header & 0xE0;
        uint8_t type = header & 0x1F;

        uint8_t fu_indicator = nri | static_cast<uint8_t>(NalType::FU_A);
        
        size_t remaining = nalu.size - 1; // skip original header
        const uint8_t* ptr = nalu.data + 1;
        
        bool start = true;
        while (remaining > 0) {
            size_t chunk_size = std::min(remaining, max_payload_size - 2);
            bool end = (chunk_size == remaining);

            uint8_t fu_header = type;
            if (start) fu_header |= 0x80;
            if (end) fu_header |= 0x40;

            std::vector<uint8_t> pkt;
            pkt.reserve(chunk_size + 2);
            pkt.push_back(fu_indicator);
            pkt.push_back(fu_header);
            pkt.insert(pkt.end(), ptr, ptr + chunk_size);
            
            packets.push_back(pkt);
            
            ptr += chunk_size;
            remaining -= chunk_size;
            start = false;
        }
    }

    return packets;
}

} // namespace nit::osnova::media
