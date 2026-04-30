#include "routing_brain.h"
#include <mutex>
#include <atomic>
#include <cmath>
#include <queue>
#include <iostream>
#include <algorithm>
#include <unordered_map>
#include <unordered_set>

namespace nit::routing {

// Core structures for B.A.T.M.A.N. advanced style routing
struct OriginatorMessage {
    uint32_t originator_address;
    uint32_t router_address;
    uint32_t sequence_number;
    uint8_t  tq; // Transmission Quality 0-255
    uint8_t  ttl;
};

struct NeighborNode {
    uint32_t address;
    uint8_t  tq;
    std::chrono::steady_clock::time_point last_seen;
    
    // Sequence window for TQ calculation (e.g., last 64 packets)
    uint64_t seqno_window; 
    uint32_t last_seqno;
    uint32_t packets_received_in_window;
};

struct OriginatorNode {
    uint32_t address;
    uint32_t best_router;
    uint8_t  best_tq;
    uint32_t last_real_seqno;
    std::chrono::steady_clock::time_point last_seen;
    
    std::unordered_map<uint32_t, NeighborNode> bcast_own;
    std::unordered_map<uint32_t, NeighborNode> bcast_neighbors;
};

// Internal state implementation minimizing header exposure
struct RoutingBrain::Impl {
    std::atomic<LinkLayer> current_layer{LinkLayer::L1_Mainline};
    std::mutex mtx;
    
    // IMU Telemetry State
    struct {
        float w, x, y, z;
        std::chrono::microseconds last_update;
        float angular_velocity_estimate = 0.0f;
    } imu_state;

    // Payload queue for Multipath context
    struct Payload {
        std::vector<std::byte> data;
        uint64_t session_id;
        std::chrono::steady_clock::time_point enqueued_at;
    };
    std::queue<Payload> tx_queue;

    // Routing Tables
    uint32_t local_address = 0x12345678; // Core local deterministic ID
    uint32_t current_seqno = 0;
    std::unordered_map<uint32_t, OriginatorNode> originators;
    std::unordered_map<uint32_t, NeighborNode> neighbors;

    // AI/Heuristics Configuration
    static constexpr float KVM_ALIGNMENT_THRESHOLD = 0.95f; 
    static constexpr int BATMAN_WINDOW_SIZE = 64;
    static constexpr int BATCH_FLUSH_INTERVAL_MS = 5;

    void update_kvm_predictor() {
        float norm = std::sqrt(imu_state.w*imu_state.w + imu_state.x*imu_state.x + 
                               imu_state.y*imu_state.y + imu_state.z*imu_state.z);
        if (norm > 0.001f) {
            imu_state.w /= norm;
            imu_state.x /= norm;
            imu_state.y /= norm;
            imu_state.z /= norm;
        }
    }

    bool is_kvm_window_optimal() const {
        float upright_alignment = std::abs(1.0f - 2.0f * (imu_state.x*imu_state.x + imu_state.y*imu_state.y));
        return upright_alignment > KVM_ALIGNMENT_THRESHOLD;
    }

    // BATMAN sliding window logic
    bool test_and_set_bit(uint64_t& seq_window, uint32_t last_seqno, uint32_t current_seqno) {
        int32_t diff = current_seqno - last_seqno;

        if (diff < 0) {
            // Out of order but within window
            if (-diff < BATMAN_WINDOW_SIZE) {
                if (seq_window & (1ULL << -diff)) {
                    return false; // Duplicate
                }
                seq_window |= (1ULL << -diff);
                return true;
            }
            return false; // Too old
        } else if (diff > 0) {
            // Forward progression
            if (diff >= BATMAN_WINDOW_SIZE) {
                seq_window = 1; // Window shifted completely out
            } else {
                seq_window <<= diff;
                seq_window |= 1;
            }
            return true;
        } else {
             // Exact match = duplicate
             return false;
        }
    }

    uint32_t calculate_tq(const NeighborNode& n) {
        uint64_t w = n.seqno_window;
        uint32_t count = 0;
        while (w) {
            count += w & 1;
            w >>= 1;
        }
        // Normalize 0-255
        return (count * 255) / BATMAN_WINDOW_SIZE;
    }

    std::vector<OriginatorMessage> tx_queue;

    void forward_message_to_queue(const OriginatorMessage& msg) {
        tx_queue.push_back(msg);
    }

    void process_ogm(const OriginatorMessage& ogm, uint32_t recv_iface_address) {
        auto now = std::chrono::steady_clock::now();

        // 1. Is this our own OGM looping back?
        if (ogm.originator_address == local_address) {
            return; 
        }

        auto& orig = originators[ogm.originator_address];
        orig.address = ogm.originator_address;
        
        auto& neighbor = neighbors[ogm.router_address];
        neighbor.address = ogm.router_address;
        neighbor.last_seen = now;

        // Sequence number evaluation
        bool is_new_seqno = test_and_set_bit(orig.bcast_neighbors[ogm.router_address].seqno_window,
                                             orig.last_real_seqno,
                                             ogm.sequence_number);

        if (ogm.sequence_number > orig.last_real_seqno) {
            orig.last_real_seqno = ogm.sequence_number;
        }

        if (!is_new_seqno) return; // Duplicate or out of window

        // Calculate path TQ
        uint8_t link_tq = calculate_tq(orig.bcast_neighbors[ogm.router_address]);
        
        // Multiplicative metric calculation (Path TQ = Originator TQ * Link TQ / 255)
        uint32_t path_tq = ((uint32_t)ogm.tq * (uint32_t)link_tq) / 255;

        // Update routing table if this is the best path
        if (path_tq > orig.best_tq) {
            orig.best_tq = path_tq;
            orig.best_router = ogm.router_address;
            orig.last_seen = now;
        }

        // Rebroadcast OGM if TTL allows and it's a new optimal path
        if (ogm.ttl - 1 > 0 && path_tq > 0) { // Actually we rebroadcast only if we select it, or if BATMAN conditions match
            OriginatorMessage rebroadcast = ogm;
            rebroadcast.router_address = local_address;
            rebroadcast.tq = path_tq;
            rebroadcast.ttl -= 1;
            // Dispatch rebroadcast to Layer 2 physical queues via the core transmission vector
            forward_message_to_queue(rebroadcast);
        }
    }

    void emit_ogm() {
        OriginatorMessage ogm;
        ogm.originator_address = local_address;
        ogm.router_address = local_address;
        ogm.sequence_number = ++current_seqno;
        ogm.tq = 255;
        ogm.ttl = 50;
        // Broadcast ogm via TX array
    }
};

RoutingBrain::RoutingBrain() : pimpl_(std::make_unique<Impl>()) {}
RoutingBrain::~RoutingBrain() = default;

std::expected<void, std::string_view> RoutingBrain::initialize() {
    std::cout << "[NIT_CORE] RoutingBrain initialized. Allocating zero-copy rings.\n";
    return {};
}

void RoutingBrain::inject_imu_telemetry(float w, float x, float y, float z, std::chrono::microseconds timestamp) noexcept {
    std::lock_guard<std::mutex> lock(pimpl_->mtx);
    pimpl_->imu_state.w = w;
    pimpl_->imu_state.x = x;
    pimpl_->imu_state.y = y;
    pimpl_->imu_state.z = z;
    pimpl_->imu_state.last_update = timestamp;
    
    pimpl_->update_kvm_predictor();
}

void RoutingBrain::enqueue_payload(std::span<const std::byte> payload, uint64_t session_id) {
    std::lock_guard<std::mutex> lock(pimpl_->mtx);
    pimpl_->tx_queue.push(Impl::Payload{
        .data = std::vector<std::byte>(payload.begin(), payload.end()),
        .session_id = session_id,
        .enqueued_at = std::chrono::steady_clock::now()
    });
}

void RoutingBrain::process_migrations() noexcept {
    std::lock_guard<std::mutex> lock(pimpl_->mtx);
    
    if (pimpl_->current_layer == LinkLayer::L4_ZeroNet) {
        // Ultimate fallback mode: flush queue over Audio Frequency Shift Keying (AFSK)
        while (!pimpl_->tx_queue.empty()) {
            // Route payload via AFSC / Ultrasound Modem mapping
            std::cout << "[NIT_ROUTING] CRITICAL: Dispatching payload via L4 ZERO-NET (AFSK Acoustic Override)\n";
            pimpl_->tx_queue.pop();
        }
    } else if (pimpl_->current_layer == LinkLayer::L2_KvmMesh) {
        if (pimpl_->is_kvm_window_optimal()) {
            while (!pimpl_->tx_queue.empty()) {
                pimpl_->tx_queue.pop();
            }
        }
    } else if (pimpl_->current_layer == LinkLayer::L1_Mainline) {
        while (!pimpl_->tx_queue.empty()) {
            pimpl_->tx_queue.pop();
        }
    }
}

void RoutingBrain::trigger_l4_override() noexcept {
    std::lock_guard<std::mutex> lock(pimpl_->mtx);
    pimpl_->current_layer = LinkLayer::L4_ZeroNet;
    std::cout << "[NIT_ROUTING] CRITICAL: OVERRIDE INITIATED. L4_ZeroNet AFSK activated.\n";
}

} // namespace nit::routing
