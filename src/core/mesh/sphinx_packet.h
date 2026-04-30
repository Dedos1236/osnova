#pragma once

#include "src/core/crypto/curve25519.h"
#include <cstdint>
#include <span>
#include <vector>
#include <array>
#include <memory>
#include <optional>

namespace nit::osnova::mesh {

/**
 * @brief Sphinx Packet Format for Anonymous Onion Routing in OSNOVA.
 * 
 * Sphinx provides provably secure, compact onion routing with indistinguishable 
 * replies and forward-secrecy, resistant to traffic analysis.
 */
class SphinxPacket {
public:
    static constexpr size_t KEY_SIZE = 32;
    static constexpr size_t MAC_SIZE = 16;
    static constexpr size_t MAX_HOPS = 5;
    static constexpr size_t ROUTING_INFO_SIZE = (MAX_HOPS * 32) + MAC_SIZE; 
    static constexpr size_t PAYLOAD_SIZE = 1024;
    static constexpr size_t PACKET_SIZE = 32 /* Alpha */ + ROUTING_INFO_SIZE /* Beta */ + MAC_SIZE /* Gamma */ + PAYLOAD_SIZE /* Delta */;

    struct RouteNode {
        uint8_t address[32]; // Next hop identifier
        uint8_t pubkey[KEY_SIZE]; // Next hop curve25519 public key
    };

    SphinxPacket();
    ~SphinxPacket();

    /**
     * @brief Create an onion-encrypted Sphinx packet.
     * 
     * @param out_packet Output buffer (must map exactly to PACKET_SIZE).
     * @param payload The raw payload to deliver to the final destination.
     * @param route The ordered list of nodes in the circuit (max MAX_HOPS).
     * @param final_destination The destination address bytes.
     * @return true on success.
     */
    bool create_packet(
        std::span<uint8_t, PACKET_SIZE> out_packet,
        std::span<const uint8_t> payload,
        const std::vector<RouteNode>& route,
        std::span<const uint8_t, 32> final_destination);

    /**
     * @brief Process and unwrap a layer of a Sphinx packet (used by intermediate relays).
     * 
     * @param out_next_hop Returns the address of the next hop (or empty if it's the final hop).
     * @param out_forward_packet The unwrapped packet to forward.
     * @param in_packet The received Sphinx packet.
     * @param relay_private_key The relay's private key.
     * @return true if MAC verification and unwrapping succeeds, false if tampared.
     */
    bool process_packet(
        std::vector<uint8_t>& out_next_hop,
        std::vector<uint8_t>& out_forward_packet,
        std::span<const uint8_t, PACKET_SIZE> in_packet,
        std::span<const uint8_t, KEY_SIZE> relay_private_key);

private:
    struct Impl;
    std::unique_ptr<Impl> pimpl_;
};

} // namespace nit::osnova::mesh
