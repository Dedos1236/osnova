#pragma once

#include <cstdint>
#include <vector>
#include <mutex>
#include <unordered_map>
#include <memory>
#include <functional>
#include "../crypto/osnova_crypto_engine.h"
#include "kvm_clock.h"

namespace nit::mesh {

using NodeId = uint64_t;

struct NeighborState {
    NodeId id;
    int rssi; // Signal strength
    uint32_t last_seen_ms;
    uint32_t rtt_ms;
    bool is_direct_link;
    nit::crypto::osnova::HybridPublicKey public_key;
};

struct OriginatorMessage {
    NodeId originator_id;
    NodeId sender_id;
    uint32_t sequence_number;
    uint8_t tq;  // Transmission Quality
    uint8_t ttl; // Time to live
};

/**
 * @brief Dynamic Routing Table for KVM Mesh using B.A.T.M.A.N IV Protocol logic.
 */
class MeshRoutingTable {
public:
    MeshRoutingTable() = default;

    /**
     * @brief Receive an Originator Message (OGM) and update routing geometry
     * @return true if the OGM should be rebroadcasted, false if dropped (duplicate/stale)
     */
    bool handle_ogm(const OriginatorMessage& ogm, uint64_t current_time_ms);
    
    // Explicit static path insertion
    void update_route(NodeId target, NodeId next_hop, uint8_t metrics);
    
    [[nodiscard]] NodeId get_best_next_hop(NodeId target);
    void prune_dead_routes(uint64_t current_time_ms);

private:
    struct RouteEntry {
        NodeId next_hop;
        uint32_t last_seq_num;
        uint8_t tq; // 0-100 Link Quality
        uint64_t last_updated;
    };
    
    std::mutex mtx_;
    std::unordered_map<NodeId, RouteEntry> table_;
};

/**
 * @brief The Core Mesh Node.
 * Manages the Bluetooth/WiFi-Direct ad-hoc graph state using 
 * Proactive Distance Vector (BATMAN).
 */
class MeshNode {
public:
    explicit MeshNode(NodeId my_id) noexcept;
    ~MeshNode();

    // Prevent copies
    MeshNode(const MeshNode&) = delete;
    MeshNode& operator=(const MeshNode&) = delete;

    [[nodiscard]] NodeId get_id() const noexcept { return my_id_; }

    void add_neighbor(const NeighborState& state);
    void remove_neighbor(NodeId id);

    KvmClock& get_clock() { return clock_; }
    MeshRoutingTable& get_routing_table() { return routing_table_; }

    // Broadcast our own OGM 
    OriginatorMessage generate_own_ogm();
    
    // Process external OGM with physical layer metrics
    void receive_ogm(const OriginatorMessage& ogm, int rssi, double frequency_mhz, double snr_db);
    
    // Callback to transmit
    std::function<void(const OriginatorMessage&)> on_rebroadcast_ogm;

private:
    NodeId my_id_;
    uint32_t sequence_number_ = 0;
    KvmClock clock_;
    MeshRoutingTable routing_table_;
    
    std::mutex neighbor_mtx_;
    std::unordered_map<NodeId, NeighborState> neighbors_;
};

} // namespace nit::mesh
