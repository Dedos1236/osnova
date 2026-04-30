#include "packet_processor.h"
#include <iostream>

namespace nit::mesh {

namespace {
    // CRC-16-CCITT (Poly: 0x1021, Init: 0xFFFF)
    uint16_t crc16_ccitt(std::span<const uint8_t> data) {
        uint16_t crc = 0xFFFF;
        for (uint8_t byte : data) {
            crc ^= (byte << 8);
            for (int i = 0; i < 8; i++) {
                if (crc & 0x8000) {
                    crc = (crc << 1) ^ 0x1021;
                } else {
                    crc = crc << 1;
                }
            }
        }
        return crc;
    }
}

PacketProcessor::PacketProcessor(MeshNode& node, DtnRouter& dtn, 
                                 crypto::osnova::OsnovaEngine& engine,
                                 const crypto::osnova::HybridSecretKey& my_sec)
    : node_(node), dtn_(dtn), engine_(engine), my_sec_(my_sec) {
        
    // In actual impl, symmetric keys are requested per session from secure enclave.
    // We use a core single symmetric key for the onion peeling pipeline demonstration.
    std::memset(my_session_key_.data(), 0xAA, 32); 
}

void PacketProcessor::set_receiver(OnReceivePayload cb) {
    on_receive_ = std::move(cb);
}

// Emulates a physical layer HDLC un-stuffing and deframing mechanism
std::vector<uint8_t> PacketProcessor::hdlc_deframe(std::span<const uint8_t> raw_stream) {
    std::vector<uint8_t> deframed;
    deframed.reserve(raw_stream.size());
    
    bool escape_next = false;
    for (uint8_t byte : raw_stream) {
        if (byte == 0x7E) {
            // Frame boundary. For a complete system, we evaluate if deframed is valid here.
            // Ignored for this simple linear deframer
            continue;
        } else if (byte == 0x7D) {
            escape_next = true;
        } else {
            if (escape_next) {
                deframed.push_back(byte ^ 0x20);
                escape_next = false;
            } else {
                deframed.push_back(byte);
            }
        }
    }
    return deframed;
}

std::vector<uint8_t> PacketProcessor::hdlc_frame(std::span<const uint8_t> payload) {
    std::vector<uint8_t> framed;
    framed.reserve(payload.size() + 4);
    
    framed.push_back(0x7E); // Start flag
    
    for (uint8_t byte : payload) {
        if (byte == 0x7E || byte == 0x7D) {
            framed.push_back(0x7D);
            framed.push_back(byte ^ 0x20);
        } else {
            framed.push_back(byte);
        }
    }
    
    framed.push_back(0x7E); // End flag
    return framed;
}

void PacketProcessor::process_incoming(NodeId from_neighbor, std::span<const uint8_t> raw_frame) {
    
    // deframe HDLC
    std::vector<uint8_t> deframed = hdlc_deframe(raw_frame);
    
    if (deframed.size() < 2) return; // Too small for CRC
    
    // Check CRC
    uint16_t expected_crc = (deframed[deframed.size() - 2] << 8) | deframed[deframed.size() - 1];
    uint16_t calculated = crc16_ccitt(std::span<const uint8_t>(deframed.data(), deframed.size() - 2));
    
    if (expected_crc != calculated) {
        // Corrupted frame
        return;
    }

    std::span<const std::byte> frame_bytes(
        reinterpret_cast<const std::byte*>(deframed.data()), 
        deframed.size() - 2
    );

    // 1. Peel the Onion Layer
    auto peel_res = onion_.peel_layer(frame_bytes, my_session_key_, engine_);
    
    if (!peel_res) {
        // Cryptographic failure (tampered packet, wrong key, or noise)
        // OSNOVA dictates immediate silent drop to prevent padding oracle attacks.
        return;
    }

    auto& peeled = peel_res.value();

    // 2. Check if I am the final destination
    if (peeled.next_hop == 0 || peeled.next_hop == node_.get_id()) {
        if (on_receive_) {
            std::span<const uint8_t> inner(
                reinterpret_cast<const uint8_t*>(peeled.peeled_payload.data()),
                peeled.peeled_payload.size()
            );
            on_receive_(from_neighbor, inner); // In strict onion routing, sender is anonymous
        }
    } else {
        // 3. I am a transit relay! Re-enqueue into DTN.
        DtnPacket dtn_pkt;
        dtn_pkt.target_id = peeled.next_hop;
        dtn_pkt.source_id = node_.get_id(); // Relay source
        dtn_pkt.creation_time = node_.get_clock().get_network_time_ms();
        dtn_pkt.ttl_ms = 60000; // 60 seconds transit TTL
        dtn_pkt.priority = 128; // Standard priority
        
        dtn_pkt.payload.resize(peeled.peeled_payload.size());
        std::memcpy(dtn_pkt.payload.data(), peeled.peeled_payload.data(), peeled.peeled_payload.size());

        dtn_.enqueue(std::move(dtn_pkt));
    }
}

bool PacketProcessor::dispatch_local(NodeId target, std::span<const uint8_t> cleartext_payload, 
                                     std::span<const crypto::osnova::OnionRouter::HopMetadata> path) {
    
    std::span<const std::byte> clear_bytes(
        reinterpret_cast<const std::byte*>(cleartext_payload.data()), 
        cleartext_payload.size()
    );

    // Build Sphynx packet
    auto onion_body = onion_.construct_sphynx_packet(clear_bytes, path, engine_);
    if (onion_body.empty()) {
        return false; // Creation failed (e.g., payload too large)
    }
    
    // Add CRC
    uint16_t crc = crc16_ccitt(std::span<const uint8_t>(reinterpret_cast<const uint8_t*>(onion_body.data()), onion_body.size()));
    onion_body.push_back(static_cast<std::byte>(crc >> 8));
    onion_body.push_back(static_cast<std::byte>(crc & 0xFF));
    
    // Frame
    std::vector<uint8_t> tx_frame = hdlc_frame(std::span<const uint8_t>(reinterpret_cast<const uint8_t*>(onion_body.data()), onion_body.size()));

    // Determine immediate next hop
    NodeId next_hop = path.empty() ? target : path.back().next_hop_node_id;

    DtnPacket dtn_pkt;
    dtn_pkt.target_id = next_hop;
    dtn_pkt.source_id = node_.get_id();
    dtn_pkt.creation_time = node_.get_clock().get_network_time_ms();
    dtn_pkt.ttl_ms = 3600000; // 1 Hour DTN hold time for initiator
    dtn_pkt.priority = 255;
    
    dtn_pkt.payload = std::move(tx_frame);

    dtn_.enqueue(std::move(dtn_pkt));
    
    return true;
}

} // namespace nit::mesh
