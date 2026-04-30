#include "mesh_node.h"
#include <algorithm>

namespace nit::mesh {

// --- Routing Table ---

bool MeshRoutingTable::handle_ogm(const OriginatorMessage& ogm, uint64_t current_time_ms) {
    std::lock_guard<std::mutex> lock(mtx_);
    auto it = table_.find(ogm.originator_id);
    
    // First setup, or sequence number is explicitly newer 
    // Dealing with sequence number wrap around (RFC 1982)
    bool is_newer = false;
    if (it == table_.end()) {
        is_newer = true;
    } else {
        uint32_t current_seq = it->second.last_seq_num;
        uint32_t new_seq = ogm.sequence_number;
        
        // Sequence number arithmetic for bounds tracking
        int32_t diff = static_cast<int32_t>(new_seq - current_seq);
        if (diff > 0) {
            is_newer = true;
        } else if (diff == 0) {
            // Sequence numbers match. Did it come via a much better route?
            // Hysteresis calculation: prefer existing unless significantly better
            if (ogm.tq > (it->second.tq * 1.2)) {
                is_newer = true;
            }
        }
    }
    
    if (is_newer) {
        // Drop dead loops
        if (ogm.tq == 0 || ogm.ttl == 0) return false;
        
        table_[ogm.originator_id] = {
            ogm.sender_id, // We route towards the sender 
            ogm.sequence_number,
            ogm.tq,
            current_time_ms
        };
        return true; // Please rebroadcast
    }
    
    return false; // Stale or worse path
}

void MeshRoutingTable::update_route(NodeId target, NodeId next_hop, uint8_t metrics) {
    std::lock_guard<std::mutex> lock(mtx_);
    auto it = table_.find(target);
    if (it == table_.end() || it->second.tq < metrics) {
        // OSNOVA metric optimization: overwrite if it's a newer better static route
        table_[target] = {next_hop, 0, metrics, 0}; // 0 = initial epoch time
    }
}

NodeId MeshRoutingTable::get_best_next_hop(NodeId target) {
    std::lock_guard<std::mutex> lock(mtx_);
    auto it = table_.find(target);
    if (it != table_.end()) {
        return it->second.next_hop;
    }
    return 0; // Return 0 for 'no route' or broadcast
}

void MeshRoutingTable::prune_dead_routes(uint64_t current_time_ms) {
    std::lock_guard<std::mutex> lock(mtx_);
    for (auto it = table_.begin(); it != table_.end(); ) {
        if (current_time_ms - it->second.last_updated > 15000) { // 15 sec expiry
            it = table_.erase(it);
        } else {
            ++it;
        }
    }
}

// --- Mesh Node ---

MeshNode::MeshNode(NodeId my_id) noexcept : my_id_(my_id) {}

MeshNode::~MeshNode() = default;

void MeshNode::add_neighbor(const NeighborState& state) {
    std::lock_guard<std::mutex> lock(neighbor_mtx_);
    neighbors_[state.id] = state;
    
    // A direct neighbor is automatically a 1-hop route to themselves
    routing_table_.update_route(state.id, state.id, 100); 
}

void MeshNode::remove_neighbor(NodeId id) {
    std::lock_guard<std::mutex> lock(neighbor_mtx_);
    neighbors_.erase(id);
}

OriginatorMessage MeshNode::generate_own_ogm() {
    OriginatorMessage ogm;
    ogm.originator_id = my_id_;
    ogm.sender_id = my_id_;
    ogm.sequence_number = sequence_number_++;
    ogm.tq = 255; // Initial transmission quality is perfect
    ogm.ttl = 50; // Initial TTL bound
    return ogm;
}

void MeshNode::receive_ogm(const OriginatorMessage& ogm, int rssi, double frequency_mhz, double snr_db) {
    if (ogm.originator_id == my_id_) return; // Filter our own echoed messages
    if (ogm.ttl <= 1) return; // Drop dying messages

    // Forwarding logic through routing
    OriginatorMessage rebroadcast_msg = ogm;
    rebroadcast_msg.sender_id = my_id_; // We are the new sender
    rebroadcast_msg.ttl -= 1;
    
    // Physical Layer Penalty calculation
    // Free Space Path Loss (FSPL) and SNR-based degradation
    // FSPL (dB) = 20 * log10(d) + 20 * log10(f) + 32.44
    // Here we approximate TQ penalty based on inverse relationship to SNR and RSSI drop
    double link_margin = rssi + snr_db - (-100.0 /* arbitrary noise floor */);
    if (link_margin < 0) link_margin = 0;
    
    // Asymmetric Link Penalty mapping to B.A.T.M.A.N. TQ scale (0-255)
    uint32_t base_penalty = 240; 
    if (link_margin < 10) base_penalty = 180; // High decay if margin is bad
    else if (link_margin < 20) base_penalty = 210;
    else base_penalty = 250; // Good margin
    
    // TQ = TQ * (Penalty / 255)
    uint32_t tq_calc = (static_cast<uint32_t>(rebroadcast_msg.tq) * base_penalty) / 255;
    rebroadcast_msg.tq = std::max<uint8_t>(1, static_cast<uint8_t>(tq_calc));

    if (routing_table_.handle_ogm(rebroadcast_msg, clock_.get_time_ms())) {
        if (on_rebroadcast_ogm) {
            on_rebroadcast_ogm(rebroadcast_msg);
        }
    }
}

} // namespace nit::mesh
