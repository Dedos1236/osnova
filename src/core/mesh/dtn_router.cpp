#include "dtn_router.h"
#include <algorithm>

namespace nit::mesh {

DtnRouter::DtnRouter(MeshNode& local_node, size_t max_store_bytes)
    : node_(local_node), max_store_bytes_(max_store_bytes) {}

void DtnRouter::enqueue(DtnPacket packet) {
    std::lock_guard<std::mutex> lock(mtx_);

    size_t packet_size = packet.payload.size() + sizeof(DtnPacket);

    // Eviction policy if out of memory
    if (current_store_bytes_ + packet_size > max_store_bytes_) {
        // Sort effectively to push lowest priority or oldest to end
        // Queue bound enforcement: drop lowest priority
        auto it = std::min_element(store_.begin(), store_.end(), 
            [](const DtnPacket& a, const DtnPacket& b) {
                if (a.priority == b.priority) return a.creation_time < b.creation_time;
                return a.priority < b.priority;
            });

        if (it != store_.end() && it->priority <= packet.priority) {
            current_store_bytes_ -= (it->payload.size() + sizeof(DtnPacket));
            store_.erase(it);
        } else {
            // Unwilling to drop higher/equal priority packets to fit this one
            return;
        }
    }

    current_store_bytes_ += packet_size;
    store_.push_back(std::move(packet));
}

std::vector<DtnPacket> DtnRouter::flush_for_neighbor(NodeId neighbor_id) {
    std::lock_guard<std::mutex> lock(mtx_);
    std::vector<DtnPacket> ready_packets;

    uint64_t now = node_.get_clock().get_network_time_ms();

    for (auto it = store_.begin(); it != store_.end(); ) {
        // Is it expired?
        if (now - it->creation_time > it->ttl_ms) {
            current_store_bytes_ -= (it->payload.size() + sizeof(DtnPacket));
            it = store_.erase(it);
            continue;
        }

        // Is this neighbor the target, or the best next hop?
        NodeId best_hop = node_.get_routing_table().get_best_next_hop(it->target_id);
        
        if (it->target_id == neighbor_id || best_hop == neighbor_id) {
            ready_packets.push_back(*it); // Copy
            current_store_bytes_ -= (it->payload.size() + sizeof(DtnPacket));
            it = store_.erase(it);
        } else {
            ++it;
        }
    }

    return ready_packets;
}

void DtnRouter::tick_cleanup() {
    std::lock_guard<std::mutex> lock(mtx_);
    uint64_t now = node_.get_clock().get_network_time_ms();

    for (auto it = store_.begin(); it != store_.end(); ) {
        if (now - it->creation_time > it->ttl_ms) {
            current_store_bytes_ -= (it->payload.size() + sizeof(DtnPacket));
            it = store_.erase(it);
        } else {
            ++it;
        }
    }
}

} // namespace nit::mesh
