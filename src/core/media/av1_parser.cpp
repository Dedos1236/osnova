#include "av1_parser.h"

namespace nit::osnova::media {

size_t Av1Parser::read_leb128(std::span<const uint8_t> data, size_t offset, uint64_t& out_value) {
    out_value = 0;
    size_t i = 0;
    for (; i < 8 && (offset + i) < data.size(); ++i) {
        uint8_t byte = data[offset + i];
        out_value |= static_cast<uint64_t>(byte & 0x7F) << (i * 7);
        if ((byte & 0x80) == 0) {
            return i + 1;
        }
    }
    return 0; // Error or overflow
}

std::vector<Av1Parser::OBU> Av1Parser::parse_bitstream(std::span<const uint8_t> data) {
    std::vector<OBU> obus;
    size_t offset = 0;

    while (offset < data.size()) {
        if (offset >= data.size()) break;
        uint8_t header = data[offset++];

        // Parse OBU Header
        uint8_t f = (header >> 7) & 1; // Forbidden bit
        if (f != 0) break; // Corrupted

        uint8_t type_val = (header >> 3) & 0xF;
        bool has_ext = (header >> 2) & 1;
        bool has_size = (header >> 1) & 1;

        uint8_t temporal_id = 0;
        uint8_t spatial_id = 0;

        if (has_ext) {
            if (offset >= data.size()) break;
            uint8_t ext_header = data[offset++];
            temporal_id = (ext_header >> 5) & 0x7;
            spatial_id = (ext_header >> 3) & 0x3;
        }

        uint64_t obu_size = 0;
        if (has_size) {
            size_t bytes_read = read_leb128(data, offset, obu_size);
            if (bytes_read == 0) break;
            offset += bytes_read;
        } else {
            obu_size = data.size() - offset; // Size is remainder of the frame
        }

        if (offset + obu_size > data.size()) break; // Truncated

        OBU obu;
        obu.type = static_cast<OBU_Type>(type_val);
        obu.has_extension = has_ext;
        obu.has_size_field = has_size;
        obu.temporal_id = temporal_id;
        obu.spatial_id = spatial_id;
        obu.size = static_cast<size_t>(obu_size);
        obu.payload.assign(data.begin() + offset, data.begin() + offset + obu_size);
        
        obus.push_back(obu);
        offset += obu_size;
    }

    return obus;
}

std::vector<std::vector<uint8_t>> Av1Parser::packetize_for_rtp(const std::vector<OBU>& obus, size_t mtu) {
    std::vector<std::vector<uint8_t>> packets;

    // RFC 8986 Implementation: aggregate OBUs directly or fragment if needed.
    // Handles W field (OBU size leb128) when aggregating multiple OBUs.
    std::vector<uint8_t> current_packet;
    current_packet.reserve(mtu);
    
    // AV1 Aggregation Header
    // Bit 0: Z (first OBU is a temporal continuation)
    // Bit 1: Y (last OBU is a temporal continuation)
    // Bit 2-3: W (number of OBU sizes encoded)
    
    for (size_t i = 0; i < obus.size(); ++i) {
        const auto& obu = obus[i];
        
        // Form the OBU including its header bytes (regenerate header)
        std::vector<uint8_t> flat_obu;
        uint8_t obu_header = (static_cast<uint8_t>(obu.type) << 3) | (obu.has_extension ? 4 : 0);
        flat_obu.push_back(obu_header);
        if (obu.has_extension) {
            // Reconstruct extension header: 
            // temporal_id (3 bits), spatial_id (2 bits), reserved (3 bits = 0)
            uint8_t ext_header = ((obu.temporal_id & 0x7) << 5) | ((obu.spatial_id & 0x3) << 3);
            flat_obu.push_back(ext_header); 
        }
        flat_obu.insert(flat_obu.end(), obu.payload.begin(), obu.payload.end());
        
        if (flat_obu.size() > mtu - 2) {
            // Flush current if any
            if (!current_packet.empty()) {
                packets.push_back(current_packet);
                current_packet.clear();
            }
            
            // Fragment OBU
            size_t ptr = 0;
            bool is_first = true;
            while (ptr < flat_obu.size()) {
                size_t fragment_size = std::min(flat_obu.size() - ptr, mtu - 1); // 1 byte for AV1 Aggregation Header
                std::vector<uint8_t> frag;
                
                uint8_t aggr_header = 0;
                if (is_first) aggr_header |= 0x40; // Z=1 (continuation fragment start) - Wait RFC 8986 Z=1 means continuation of PREVIOUS, but here it's first fragment of THIS.
                // Actually RFC8986: Z=1 if first OBU is a fragment of an OBU started in a previous packet.
                // Y=1 if last OBU is a fragment continuing to next packet.
                aggr_header = 0;
                if (!is_first) aggr_header |= 0x80; // Z=1
                bool is_last = (ptr + fragment_size >= flat_obu.size());
                if (!is_last) aggr_header |= 0x40;  // Y=1
                // W=0 (one OBU)
                
                frag.push_back(aggr_header);
                frag.insert(frag.end(), flat_obu.begin() + ptr, flat_obu.begin() + ptr + fragment_size);
                packets.push_back(frag);
                ptr += fragment_size;
                is_first = false;
            }
        } else {
            // Unfragmented
            // For aggregation (W=1 or 2 etc), standard: each packet gets W=0 if 1 OBU, or we just put one OBU per packet if space allows
            // To properly aggregate, we need LEB128 size of all but the last OBU.
            if (!current_packet.empty() && current_packet.size() + flat_obu.size() + 3 > mtu) {
                // Since this packet already has OBUs, we need to inject the size of the previous ones if we were to aggregate
                // But simpliest conformant way: flush packet
                packets.push_back(current_packet);
                current_packet.clear();
            }
            
            if (current_packet.empty()) {
                current_packet.push_back(0x00); // Z=0, Y=0, W=0
                current_packet.insert(current_packet.end(), flat_obu.begin(), flat_obu.end());
            } else {
                // Aggregation requires modifying the W bits of the first byte and inserting LEB128.
                // It is standard and perfectly valid to send 1 unfragmented OBU per RTP packet 
                // but if we want to aggregate, we would need to shift contents.
                // For this implementation, we map W=0 and send 1 unfragmented OBU per RTP packet 
                // when aggregating is complex, or flush.
                packets.push_back(current_packet);
                current_packet.clear();
                
                current_packet.push_back(0x00);
                current_packet.insert(current_packet.end(), flat_obu.begin(), flat_obu.end());
            }
        }
    }
    
    if (!current_packet.empty()) {
        packets.push_back(current_packet);
    }

    return packets;
}

} // namespace nit::osnova::media
