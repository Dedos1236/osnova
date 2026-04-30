#pragma once

#include <chrono>
#include <expected>
#include <memory>
#include <string_view>
#include <variant>
#include <vector>

namespace nit::routing {

// ============================================================================
// Types & Concepts
// ============================================================================

enum class LinkLayer : uint8_t {
    L1_Mainline = 1, // 4G/Wi-Fi (QUIC)
    L2_KvmMesh  = 2, // KVM BLE/Wi-Fi Direct
    L3_Acoustic = 3, // Ultrasonic 18-22kHz
    L4_ZeroNet  = 4  // P2P / DTN Ledger
};

struct LinkQuality {
    float latency_ms;
    float bandwidth_kbps;
    float packet_loss_ratio;
    LinkLayer active_layer;
};

// Represents the state of a single connection context (Multipath QUIC-like)
struct MultipathContext {
    uint64_t connection_id;
    LinkLayer primary_layer;
    std::vector<LinkLayer> fallback_layers;
};

// ============================================================================
// Routing Brain - The AI Balancer
// ============================================================================

/**
 * @brief Core AI-Balancer and Link Manager.
 * Handles seamless connection migration between L1 -> L4 based on ML models,
 * sensor constraints (IMU), and signal quality.
 * 
 * Design: Zero-cost bindings, lock-free queues where possible, 
 * memory-safe RAII structures.
 */
class RoutingBrain {
public:
    RoutingBrain();
    ~RoutingBrain();

    // Disabled copy/move for deterministic memory bounds
    RoutingBrain(const RoutingBrain&) = delete;
    RoutingBrain& operator=(const RoutingBrain&) = delete;
    RoutingBrain(RoutingBrain&&) = delete;
    RoutingBrain& operator=(RoutingBrain&&) = delete;

    /**
     * @brief Initialize the balancer and prepare underlying Asio contexts.
     */
    [[nodiscard]] std::expected<void, std::string_view> initialize();

    /**
     * @brief Injects 200Hz IMU quaternion data to predict the next L2 spatial alignment window.
     * @param w, x, y, z Quaternion components
     * @param timestamp System hardware timestamp for microsecond precision
     */
    void inject_imu_telemetry(float w, float x, float y, float z, std::chrono::microseconds timestamp) noexcept;

    /**
     * @brief Pushes a payload into the transmission pipeline. 
     * The Brain decides the physical L1-L4 transport route asynchronously.
     */
    void enqueue_payload(std::span<const std::byte> payload, uint64_t session_id);

    /**
     * @brief Tick function to be called in the core networking loop.
     * Evaluates link transition triggers and executes seamless connection migrations.
     */
    void process_migrations() noexcept;

    /**
     * @brief Triggers an immediate lock-step transition to L4_ZeroNet acoustic emergency beaconing.
     */
    void trigger_l4_override() noexcept;

private:
    struct Impl;
    std::unique_ptr<Impl> pimpl_;
};

} // namespace nit::routing
