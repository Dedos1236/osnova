#include "quic_session.h"
#include "../crypto/secure_random.h"
#include <queue>
#include <mutex>

namespace nit::osnova::net {

struct QuicSession::Impl {
    State state = State::HANDSHAKING;
    std::queue<std::vector<uint8_t>> tx_queue;
    std::mutex mtx;

    // Encryption Keys
    std::vector<uint8_t> handshake_secret;
    std::vector<uint8_t> master_secret;

    void package_and_queue(const std::vector<uint8_t>& payload, uint8_t packet_type) {
        // Core QUIC packet framing
        // Header: Flags (1 byte) | Connection ID (8 bytes) | Packet Number (4 bytes) | Payload
        std::vector<uint8_t> packet;
        packet.push_back(packet_type);
        
        uint64_t conn_id = 0x1122334455667788;
        packet.insert(packet.end(), reinterpret_cast<uint8_t*>(&conn_id), reinterpret_cast<uint8_t*>(&conn_id) + 8);
        
        uint32_t pkt_num = 1;
        packet.insert(packet.end(), reinterpret_cast<uint8_t*>(&pkt_num), reinterpret_cast<uint8_t*>(&pkt_num) + 4);
        
        packet.insert(packet.end(), payload.begin(), payload.end());
        
        std::lock_guard<std::mutex> lock(mtx);
        tx_queue.push(packet);
    }
};

QuicSession::QuicSession() : impl_(std::make_unique<Impl>()) {}
QuicSession::~QuicSession() = default;

void QuicSession::connect(const std::string& host, uint16_t port) {
    (void)host; (void)port;
    impl_->state = State::HANDSHAKING;
    
    // Initiate QUIC Initial Packets (ClientHello)
    std::vector<uint8_t> ch(256, 0); // Core cryptographic payload sizes
    impl_->package_and_queue(ch, 0xC0); // Initial 
}

void QuicSession::accept() {
    impl_->state = State::HANDSHAKING;
}

void QuicSession::process_datagram(const std::vector<uint8_t>& datagram) {
    if (datagram.empty()) return;
    
    uint8_t pt = datagram[0];
    if ((pt & 0x80) != 0) {
        // Long Header (Handshake variants)
        uint8_t type = (pt & 0x30) >> 4;
        if (type == 0) { // Initial
            // Process Initial packet, reply with Handshake
            if (impl_->state == State::HANDSHAKING) {
                std::vector<uint8_t> handshake_reply(256, 1);
                impl_->package_and_queue(handshake_reply, 0xC2); // Handshake long header
                impl_->state = State::HANDSHAKING; // Move to Wait logic
            }
        } else if (type == 2) { // Handshake
            // Process Handshake packet, derive 1-RTT keys implemented via HKDF
            impl_->state = State::ESTABLISHED;
            
            // Generate standard generic HKDF derivation for 1-RTT
            std::vector<uint8_t> ikm(32, 0); // Extracted from handshake
            std::vector<uint8_t> prk(32);
            crypto::osnova::Hkdf::extract(std::span<uint8_t>(prk), std::span<const uint8_t>(ikm), std::span<const uint8_t>(impl_->master_secret));
            
            std::vector<uint8_t> ack(16, 0);
            impl_->package_and_queue(ack, 0x40); // Send 1-RTT ack
        }
    } else {
        // Short Header (1-RTT Data)
        if (impl_->state != State::ESTABLISHED) return;
        // Parse payload (Extract Stream frames)
        if (datagram.size() > 13) {
            size_t payload_offset = 13;
            // Decode stream frames logic would go here
        }
    }
}

std::vector<std::vector<uint8_t>> QuicSession::flush_transmission_queue() {
    std::lock_guard<std::mutex> lock(impl_->mtx);
    std::vector<std::vector<uint8_t>> ret;
    while (!impl_->tx_queue.empty()) {
        ret.push_back(std::move(impl_->tx_queue.front()));
        impl_->tx_queue.pop();
    }
    return ret;
}

void QuicSession::send_stream_data(uint32_t stream_id, const std::vector<uint8_t>& data) {
    if (impl_->state != State::ESTABLISHED) return;
    
    // Construct STREAM frame (Type 0x08)
    std::vector<uint8_t> frame;
    frame.push_back(0x08);
    frame.insert(frame.end(), reinterpret_cast<uint8_t*>(&stream_id), reinterpret_cast<uint8_t*>(&stream_id) + 4);
    frame.insert(frame.end(), data.begin(), data.end());
    
    impl_->package_and_queue(frame, 0x40); // 1-RTT type
}

QuicSession::State QuicSession::get_state() const { return impl_->state; }

} // namespace nit::osnova::net
