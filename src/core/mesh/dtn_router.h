#pragma once

#include "mesh_node.h"
#include <vector>
#include <queue>
#include <mutex>
#include <span>

namespace nit::mesh {

struct DtnPacket {
    uint64_t target_id;
    uint64_t source_id;
    uint32_t ttl_ms;          // Time To Live in real milliseconds based on KvmClock
    uint32_t creation_time;   // KvmClock timestamp
    std::vector<uint8_t> payload; // Onion Encrypted blob
    uint8_t priority;         // 0 = low, 255 = critical
};

/**
 * @brief Delay/Disruption Tolerant Networking (DTN) Router.
 * 
 * If a node goes offline, the DTN router stores the packet until:
 * A) The TTL expires.
 * B) A physical connection to the next hop is established.
 * C) A new better route appears.
 * 
 * Memory constrained logic using priority queues.
 */
class DtnRouter {
public:
    explicit DtnRouter(MeshNode& local_node, size_t max_store_bytes = 10 * 1024 * 1024);

    // No copy
    DtnRouter(const DtnRouter&) = delete;
    DtnRouter& operator=(const DtnRouter&) = delete;

    /**
     * @brief Enqueues a packet. May block if store is full or evict lowest priority.
     */
    void enqueue(DtnPacket packet);

    /**
     * @brief Extract packets that are ready to be sent to a specific newly-connected neighbor.
     */
    std::vector<DtnPacket> flush_for_neighbor(NodeId neighbor_id);

    /**
     * @brief Housekeeping: Drop expired packets.
     */
    void tick_cleanup();

private:
    MeshNode& node_;
    size_t max_store_bytes_;
    size_t current_store_bytes_{0};

    // Thread-safe DTN Storage
    std::mutex mtx_;
    std::vector<DtnPacket> store_;
};

} // namespace nit::mesh
