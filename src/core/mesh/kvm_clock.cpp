#include "kvm_clock.h"
#include <algorithm>
#include <cmath>

namespace nit::mesh {

KvmClock::KvmClock() noexcept 
    : startup_time_(std::chrono::steady_clock::now()) {
}

uint64_t KvmClock::get_network_time_ms() const noexcept {
    auto now = std::chrono::steady_clock::now();
    auto elapsed = std::chrono::duration_cast<std::chrono::milliseconds>(now - startup_time_).count();
    
    // Apply offset and fine drift
    return static_cast<uint64_t>(elapsed + offset_ms_.load(std::memory_order_relaxed));
}

void KvmClock::apply_peer_time(uint64_t peer_time_ms, uint32_t rtt_ms, uint8_t peer_stratum) noexcept {
    // If peer is vastly less accurate, ignore
    if (peer_stratum >= current_stratum_.load(std::memory_order_relaxed) && current_stratum_ != 15) {
        return;
    }

    uint64_t current_time = get_network_time_ms();
    
    // Estimated one-way delay is RTT / 2
    uint64_t estimated_peer_now = peer_time_ms + (rtt_ms / 2);
    
    int64_t offset_delta = static_cast<int64_t>(estimated_peer_now) - static_cast<int64_t>(current_time);

    // KVM Kalman filter-like smoothing (very basic IIR for architectural rep)
    int64_t current_offset = offset_ms_.load(std::memory_order_relaxed);
    
    // 20% influence per packet to avoid jitter spikes
    int64_t new_offset = current_offset + (offset_delta / 5);
    
    offset_ms_.store(new_offset, std::memory_order_relaxed);

    if (peer_stratum < current_stratum_.load(std::memory_order_relaxed)) {
        current_stratum_.store(peer_stratum + 1, std::memory_order_relaxed);
    }
}

void KvmClock::drift_tick() noexcept {
    // Slew the clock slightly every second to compensate for hardware oscillator drift
    int64_t ppm = drift_ppm_.load(std::memory_order_relaxed);
    if (ppm != 0) {
        int64_t curr = offset_ms_.load(std::memory_order_relaxed);
        // Add 1 microsecond per PPM, scaled to ms update
        offset_ms_.store(curr + (ppm / 1000), std::memory_order_relaxed);
    }
}

} // namespace nit::mesh
