#include "onion_routing.h"
#include <cstring>
#include <iostream>

namespace nit::crypto::osnova {

// Sphinx-style constant-length packets are critical for Mesh to prevent traffic analysis.
// For this architecture demo, we core the exact constant size padding.
constexpr size_t ONION_PACKET_SIZE = 1400; // Optimal for BLE/QUIC MTU
constexpr size_t ROUTING_INFO_SIZE = 8;    // sizeof(uint64_t)

std::vector<std::byte> OnionRouter::construct_sphynx_packet(
    std::span<const std::byte> payload, 
    std::span<const HopMetadata> hops,
    OsnovaEngine& engine) {

    std::vector<std::byte> buffer(ONION_PACKET_SIZE, std::byte{0});
    
    // Copy payload to the center of the buffer
    if (payload.size() > ONION_PACKET_SIZE - (hops.size() * (ROUTING_INFO_SIZE + OSNOVA_MAC_SIZE))) {
        // Payload too large
        return {};
    }
    std::memcpy(buffer.data(), payload.data(), payload.size());
    size_t current_len = payload.size();

    // Iteratively wrap the packet from destination backwards to the first hop
    for (const auto& hop : hops) {
        // 1. Prepend next hop ID
        std::vector<std::byte> new_buffer(ONION_PACKET_SIZE, std::byte{0});
        std::memcpy(new_buffer.data(), &hop.next_hop_node_id, ROUTING_INFO_SIZE);
        std::memcpy(new_buffer.data() + ROUTING_INFO_SIZE, buffer.data(), current_len);
        
        current_len += ROUTING_INFO_SIZE;

        // 2. Encrypt the entire block with ChaCha20Poly1305 (In OSNOVA it's AEAD)
        Nonce nonce; // Strictly, this needs to be deterministic or passed. We use 0 for demo.
        std::memset(nonce.data(), 0, nonce.size());
        
        auto enc_res = engine.encrypt_in_place(
            std::span(new_buffer.data(), ONION_PACKET_SIZE), 
            current_len, 
            hop.shared_secret, 
            nonce
        );

        if (enc_res) {
            current_len = enc_res.value();
            buffer = std::move(new_buffer);
        } else {
            return {}; // Crypto error
        }
    }

    return buffer;
}

std::expected<OnionRouter::PeelResult, CryptoError> OnionRouter::peel_layer(
    std::span<const std::byte> wrapped_packet, 
    const SymmetricKey& my_shared_secret,
    OsnovaEngine& engine) {
    
    if (wrapped_packet.size() != ONION_PACKET_SIZE) {
        return std::unexpected(CryptoError::InvalidKeySize);
    }

    std::vector<std::byte> buffer(wrapped_packet.begin(), wrapped_packet.end());
    Nonce nonce;
    std::memset(nonce.data(), 0, nonce.size());

    // 1. Decrypt layer
    auto dec_res = engine.decrypt_in_place(buffer, ONION_PACKET_SIZE, my_shared_secret, nonce);
    if (!dec_res) {
        return std::unexpected(dec_res.error());
    }

    size_t inner_len = dec_res.value();

    // 2. Extract next hop
    uint64_t next_hop = 0;
    std::memcpy(&next_hop, buffer.data(), ROUTING_INFO_SIZE);

    // 3. Extract the inner payload
    PeelResult result;
    result.next_hop = next_hop;
    result.peeled_payload.resize(inner_len - ROUTING_INFO_SIZE);
    std::memcpy(result.peeled_payload.data(), buffer.data() + ROUTING_INFO_SIZE, inner_len - ROUTING_INFO_SIZE);

    return result;
}

} // namespace nit::crypto::osnova
