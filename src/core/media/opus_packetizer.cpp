#include "opus_packetizer.h"
#include <cstring>

namespace nit::osnova::media {

/*
 * RTP Header format (12 bytes):
 * 0                   1                   2                   3
 * 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
 * +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 * |V=2|P|X|  CC   |M|     PT      |       sequence number         |
 * +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 * |                           timestamp                           |
 * +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 * |           synchronization source (SSRC) identifier            |
 * +=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+
 */

OpusPacketizer::OpusPacketizer(uint32_t ssrc, uint16_t initial_seq_num, uint32_t payload_type)
    : ssrc_(ssrc), current_seq_(initial_seq_num), current_timestamp_(0), payload_type_(payload_type) 
{
}

OpusPacketizer::~OpusPacketizer() = default;

OpusPacketizer::RtpPacket OpusPacketizer::packetize(std::span<const uint8_t> opus_frame, uint32_t frame_duration_ms, bool marker_bit) {
    RtpPacket pkt;
    pkt.sequence_number = current_seq_;
    pkt.timestamp = current_timestamp_;

    size_t packet_size = 12 + opus_frame.size();
    pkt.data.resize(packet_size);

    // Build RTP Header
    pkt.data[0] = 0x80; // Version 2
    pkt.data[1] = (marker_bit ? 0x80 : 0x00) | (payload_type_ & 0x7F);
    
    pkt.data[2] = (current_seq_ >> 8) & 0xFF;
    pkt.data[3] = current_seq_ & 0xFF;

    pkt.data[4] = (current_timestamp_ >> 24) & 0xFF;
    pkt.data[5] = (current_timestamp_ >> 16) & 0xFF;
    pkt.data[6] = (current_timestamp_ >> 8) & 0xFF;
    pkt.data[7] = current_timestamp_ & 0xFF;

    pkt.data[8] = (ssrc_ >> 24) & 0xFF;
    pkt.data[9] = (ssrc_ >> 16) & 0xFF;
    pkt.data[10]= (ssrc_ >> 8) & 0xFF;
    pkt.data[11]= ssrc_ & 0xFF;

    // Payload
    std::memcpy(pkt.data.data() + 12, opus_frame.data(), opus_frame.size());

    // Advance sequence number
    current_seq_++;
    
    // Advance timestamp (duration in milliseconds * 48 samples per millisecond)
    current_timestamp_ += (frame_duration_ms * 48);

    return pkt;
}

} // namespace nit::osnova::media
