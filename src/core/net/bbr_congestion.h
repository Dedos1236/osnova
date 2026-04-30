#pragma once

#include <vector>
#include <cstdint>
#include <span>
#include <chrono>

namespace nit::osnova::net {

/**
 * @brief BBR (Bottleneck Bandwidth and Round-trip propagation time) Congestion Control.
 * Advanced congestion control model ported from Google BBR TCP implementation.
 * Solves the critical issue of buffer-bloat in loss-based congestion control (like CUBIC).
 * Ensures maximum stable UDP throughput for video streams over high-latency satellites.
 */
class BbrCongestion {
public:
    BbrCongestion();
    ~BbrCongestion();

    enum class State {
        STARTUP,
        DRAIN,
        PROBE_BW,
        PROBE_RTT
    };

    /**
     * @brief Called when a UDP packet is successfully sent out.
     */
    void on_packet_sent(uint64_t sequence_number, size_t size_bytes, uint64_t current_time_ms);

    /**
     * @brief Called when an ACK is received for previously sent packets.
     */
    void on_packet_acked(uint64_t sequence_number, size_t size_bytes, uint64_t current_time_ms);

    /**
     * @brief Called when a packet is explicitly marked lost.
     */
    void on_packet_lost(uint64_t sequence_number, size_t size_bytes, uint64_t current_time_ms);

    /**
     * @brief Returns the calculated congestion window (max bytes in flight).
     */
    uint64_t get_cwnd() const;

    /**
     * @brief Returns the ideal pacing rate calculated by BBR (bytes/second).
     */
    uint64_t get_pacing_rate() const;

private:
    State state_;
    
    uint64_t min_rtt_;
    uint64_t min_rtt_stamp_;

    uint64_t btl_bw_;     // Bottleneck Bandwidth (bytes/sec)
    uint64_t btl_bw_stamp_;
    
    uint64_t pacing_rate_;
    uint64_t cwnd_;
    uint64_t inflight_;

    // Filters for observing max bandwidth and min rtt
    struct DeliveryRateSample {
        uint64_t bytes_delivered;
        uint64_t delivery_time_delta;
    };

    void update_model_and_state(uint64_t rtt_sample, uint64_t delivery_rate_sample_bps, uint64_t now);
    void enter_startup();
    void enter_drain();
    void enter_probe_bw(uint64_t now);
    void enter_probe_rtt();

    int cycle_index_;
    uint64_t cycle_stamp_;
    static constexpr double PACING_GAIN_CYCLE[] = {1.25, 0.75, 1.0, 1.0, 1.0, 1.0, 1.0, 1.0};
};

} // namespace nit::osnova::net
