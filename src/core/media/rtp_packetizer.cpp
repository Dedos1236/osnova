#include "rtp_packetizer.h"
#include <cstring>
#include <arpa/inet.h>

namespace nit::osnova::media {

RtpPacketizer::RtpPacketizer(uint8_t payload_type, uint32_t ssrc)
    : payload_type_(payload_type), ssrc_(ssrc), sequence_number_(0)
{
}

RtpPacketizer::~RtpPacketizer() = default;

std::vector<uint8_t> RtpPacketizer::create_packet(
    uint32_t timestamp,
    bool marker,
    std::span<const uint8_t> payload)
{
    std::vector<uint8_t> packet;
    packet.reserve(RTP_HEADER_SIZE + payload.size());

    // Byte 0: V(2) | P(1) | X(1) | CC(4)
    uint8_t b0 = (2 << 6) | 0; // Version 2, no padding, no extensions, 0 CSRC
    packet.push_back(b0);

    // Byte 1: M(1) | PT(7)
    uint8_t b1 = (marker ? 0x80 : 0x00) | (payload_type_ & 0x7f);
    packet.push_back(b1);

    // Byte 2-3: Sequence Number
    uint16_t seq_net = htons(sequence_number_++);
    packet.push_back(seq_net & 0xFF);
    packet.push_back((seq_net >> 8) & 0xFF);

    // Byte 4-7: Timestamp
    uint32_t ts_net = htonl(timestamp);
    packet.push_back((ts_net >> 24) & 0xFF);
    packet.push_back((ts_net >> 16) & 0xFF);
    packet.push_back((ts_net >> 8) & 0xFF);
    packet.push_back(ts_net & 0xFF);

    // Byte 8-11: SSRC
    uint32_t ssrc_net = htonl(ssrc_);
    packet.push_back((ssrc_net >> 24) & 0xFF);
    packet.push_back((ssrc_net >> 16) & 0xFF);
    packet.push_back((ssrc_net >> 8) & 0xFF);
    packet.push_back(ssrc_net & 0xFF);

    // Append payload
    packet.insert(packet.end(), payload.begin(), payload.end());

    return packet;
}

bool RtpPacketizer::parse_packet(
    RtpHeader& header,
    std::vector<uint8_t>& payload,
    std::span<const uint8_t> packet)
{
    if (packet.size() < RTP_HEADER_SIZE) return false;

    uint8_t b0 = packet[0];
    header.version = (b0 >> 6) & 0x03;
    if (header.version != 2) return false;

    header.padding = (b0 >> 5) & 0x01;
    header.extension = (b0 >> 4) & 0x01;
    header.csrc_count = b0 & 0x0F;

    uint8_t b1 = packet[1];
    header.marker = (b1 >> 7) & 0x01;
    header.payload_type = b1 & 0x7F;

    uint16_t seq_net;
    std::memcpy(&seq_net, packet.data() + 2, 2);
    header.sequence_number = ntohs(seq_net);

    uint32_t ts_net;
    std::memcpy(&ts_net, packet.data() + 4, 4);
    header.timestamp = ntohl(ts_net);

    uint32_t ssrc_net;
    std::memcpy(&ssrc_net, packet.data() + 8, 4);
    header.ssrc = ntohl(ssrc_net);

    size_t header_len = RTP_HEADER_SIZE + (header.csrc_count * 4);
    if (packet.size() < header_len) return false;

    // extract CSRCs
    header.csrc_list.clear();
    for (int i = 0; i < header.csrc_count; ++i) {
        uint32_t csrc_net;
        std::memcpy(&csrc_net, packet.data() + RTP_HEADER_SIZE + (i*4), 4);
        header.csrc_list.push_back(ntohl(csrc_net));
    }

    size_t ext_len = 0;
    if (header.extension) {
        if (packet.size() < header_len + 4) return false;
        uint16_t ext_len_words;
        std::memcpy(&ext_len_words, packet.data() + header_len + 2, 2);
        ext_len = 4 + (ntohs(ext_len_words) * 4);
        if (packet.size() < header_len + ext_len) return false;
    }

    size_t payload_offset = header_len + ext_len;
    size_t payload_len = packet.size() - payload_offset;

    if (header.padding) {
        uint8_t pad_len = packet.back();
        if (pad_len > payload_len) return false;
        payload_len -= pad_len;
    }

    payload.assign(packet.begin() + payload_offset, packet.begin() + payload_offset + payload_len);

    return true;
}

} // namespace nit::osnova::media
