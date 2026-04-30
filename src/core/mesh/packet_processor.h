#pragma once

#include "mesh_node.h"
#include "dtn_router.h"
#include "../crypto/onion_routing.h"
#include "../crypto/osnova_crypto_engine.h"
#include <functional>

namespace nit::mesh {

class PacketProcessor {
public:
    PacketProcessor(MeshNode& node, DtnRouter& dtn, crypto::osnova::OsnovaEngine& engine, 
                    const crypto::osnova::HybridSecretKey& my_sec);

    /**
     * @brief Receive callback type for the final application layer.
     */
    using OnReceivePayload = std::function<void(NodeId sender, std::span<const uint8_t> payload)>;
    void set_receiver(OnReceivePayload cb);

    /**
     * @brief Process an incoming blind-routed raw frame from a neighbor.
     */
    void process_incoming(NodeId from_neighbor, std::span<const uint8_t> raw_frame);

    /**
     * @brief Build and inject a local payload into the DTN towards target.
     */
    bool dispatch_local(NodeId target, std::span<const uint8_t> cleartext_payload, 
                        std::span<const crypto::osnova::OnionRouter::HopMetadata> path);

private:
    std::vector<uint8_t> hdlc_deframe(std::span<const uint8_t> raw_stream);
    std::vector<uint8_t> hdlc_frame(std::span<const uint8_t> payload);

    MeshNode& node_;
    DtnRouter& dtn_;
    crypto::osnova::OsnovaEngine& engine_;
    crypto::osnova::OnionRouter onion_;
    const crypto::osnova::HybridSecretKey& my_sec_;
    
    // We need a shared symmetric key cache for peeling. Since we encapsulate,
    // this mimics the secure enclave hardware state.
    crypto::osnova::SymmetricKey my_session_key_;
    
    OnReceivePayload on_receive_;
};

} // namespace nit::mesh
