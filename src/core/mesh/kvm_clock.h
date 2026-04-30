#pragma once

#include <cstdint>
#include <atomic>
#include <chrono>

namespace nit::mesh {

/**
 * @brief Kinematic Vector Mesh (KVM) Time Synchronization Clock.
 * In a true Ad-Hoc mesh, time is relative. This implements a modified
 * intersection algorithm (similar to NTP/PTP) but designed for sporadically 
 * connected Bluetooth/WiFi-Direct nodes to establish a shared time consensus.
 */
class KvmClock {
public:
    KvmClock() noexcept;

    // No copy
    KvmClock(const KvmClock&) = delete;
    KvmClock& operator=(const KvmClock&) = delete;

    /**
     * @brief Gets current synchronized continuous network time in milliseconds.
     */
    [[nodiscard]] uint64_t get_network_time_ms() const noexcept;

    /**
     * @brief Call when receiving a time beacon from a peer.
     * @param peer_time_ms The time reported by the peer.
     * @param rtt_ms The measured Round-Trip-Time to the peer.
     * @param stratum The stratum level of the peer (0 = atomic, 15 = unsynced).
     */
    void apply_peer_time(uint64_t peer_time_ms, uint32_t rtt_ms, uint8_t stratum) noexcept;

    /**
     * @brief Drift adjustment (Slew)
     */
    void drift_tick() noexcept;

private:
    std::atomic<int64_t> offset_ms_{0};
    std::atomic<int64_t> drift_ppm_{0}; // Parts per million drift
    std::atomic<uint8_t> current_stratum_{15};
    
    // Base steady clock point
    std::chrono::steady_clock::time_point startup_time_;
};

} // namespace nit::mesh
