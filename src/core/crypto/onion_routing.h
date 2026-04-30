#pragma once

#include <vector>
#include <cstdint>
#include <span>
#include <string_view>
#include "osnova_crypto_engine.h"

namespace nit::crypto::osnova {

/**
 * @brief Onion Routing encapsulation (Blind Routing).
 * Packs routing metadata iteratively so transit relay nodes only see cryptographic garbage.
 */
class OnionRouter {
public:
    OnionRouter() = default;
    
    // No copy/move
    OnionRouter(const OnionRouter&) = delete;
    OnionRouter& operator=(const OnionRouter&) = delete;

    struct HopMetadata {
        uint64_t next_hop_node_id;
        std::array<std::byte, 32> shared_secret;
    };

    /**
     * @brief Wraps a raw payload into multiple encryption layers (the Onion).
     * @param payload The original L4 DTN payload.
     * @param hops Array of nodes leading to the destination in reverse order (closest node first).
     * @param engine Core to initialized OSNOVA engine
     */
    [[nodiscard]] std::vector<std::byte> construct_sphynx_packet(
        std::span<const std::byte> payload, 
        std::span<const HopMetadata> hops,
        OsnovaEngine& engine);

    /**
     * @brief Peels back one encryption layer. 
     * Used by transit nodes in L2 KVM-Mesh.
     * @return The ID of the next node to send the packet to, and the remaining peeled payload.
     *         If next_hop is 0, this node is the final destination.
     */
    struct PeelResult {
        uint64_t next_hop;
        std::vector<std::byte> peeled_payload;
    };

    [[nodiscard]] std::expected<PeelResult, CryptoError> peel_layer(
        std::span<const std::byte> wrapped_packet, 
        const SymmetricKey& my_shared_secret,
        OsnovaEngine& engine);
};

} // namespace nit::crypto::osnova
