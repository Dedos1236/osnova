#pragma once

#include <cstdint>
#include <vector>
#include <span>

namespace nit::osnova::mesh {

/**
 * @brief High-level TCP BBR Congestion Control logical core.
 * Used for QUIC-based OSNOVA flows to maximize throughput and minimize latency.
 */
class BbrCongestionControl {
public:
    BbrCongestionControl();
    ~BbrCongestionControl();

    /**
     * @brief Called when a packet is sent.
     */
    void on_packet_sent(uint64_t sequence_number, size_t bytes, uint64_t timestamp_us);

    /**
     * @brief Called when a packet's acknowledgment is received.
     */
    void on_packet_acked(uint64_t sequence_number, size_t bytes_acked, uint64_t rtt_us);

    /**
     * @brief Called when a packet is considered lost.
     */
    void on_packet_lost(uint64_t sequence_number, size_t bytes_lost);

    /**
     * @brief Get the computed pacing rate (bytes per second).
     */
    uint64_t get_pacing_rate() const;

    /**
     * @brief Get the current congestion window (bytes).
     */
    uint64_t get_congestion_window() const;

private:
    enum class State {
        STARTUP,
        DRAIN,
        PROBE_BW,
        PROBE_RTT
    };

    State state_;

    uint64_t min_rtt_us_;
    uint64_t btl_bw_bps_; // Bottleneck bandwidth
    uint64_t cwnd_;       // Congestion window
    uint64_t pacing_rate_;
    
    // Timers and counters
    uint64_t round_start_time_;
    int probe_bw_cycle_idx_;
};

} // namespace nit::osnova::mesh
