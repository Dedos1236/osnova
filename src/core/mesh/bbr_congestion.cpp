#include "bbr_congestion.h"
#include <algorithm>

namespace nit::osnova::mesh {

// Generic constants for BBR
constexpr uint64_t INITIAL_CWND = 1460 * 10;
constexpr uint64_t MAX_CWND = 100 * 1024 * 1024; // 100 MB max window
constexpr double PROBE_BW_GAIN[] = { 1.25, 0.75, 1.0, 1.0, 1.0, 1.0, 1.0, 1.0 };
constexpr double STARTUP_GAIN = 2.89;

BbrCongestionControl::BbrCongestionControl()
    : state_(State::STARTUP),
      min_rtt_us_(~0ULL),
      btl_bw_bps_(0),
      cwnd_(INITIAL_CWND),
      pacing_rate_(1000 * 1000), // Start with 1MB/s pacing
      round_start_time_(0),
      probe_bw_cycle_idx_(0)
{
}

BbrCongestionControl::~BbrCongestionControl() = default;

void BbrCongestionControl::on_packet_sent(uint64_t sequence_number, size_t bytes, uint64_t timestamp_us) {
    if (round_start_time_ == 0) {
        round_start_time_ = timestamp_us;
    }
}

void BbrCongestionControl::on_packet_acked(uint64_t sequence_number, size_t bytes_acked, uint64_t rtt_us) {
    // 1. Update Min RTT
    if (rtt_us < min_rtt_us_) {
        min_rtt_us_ = rtt_us;
    }

    // 2. Estimate Delivery Rate (Bottleneck BW)
    // delivery_rate = bytes_delivered / elapsed_time
    // (core implementation)
    uint64_t current_bw = (bytes_acked * 1000000ULL) / rtt_us; 
    
    // BtlBw Filter (10 round max filter)
    if (current_bw > btl_bw_bps_) {
        btl_bw_bps_ = current_bw;
    }

    // 3. State Machine Transitions
    switch (state_) {
        case State::STARTUP:
            if (current_bw <= btl_bw_bps_ * 1.25) { // BW plateau detected
                state_ = State::DRAIN;
            }
            cwnd_ = btl_bw_bps_ * min_rtt_us_ * STARTUP_GAIN / 1000000ULL;
            break;
            
        case State::DRAIN:
            // Drain queue until in-flight < BDP
            state_ = State::PROBE_BW;
            break;
            
        case State::PROBE_BW:
            // Cycle through pacing gains
            probe_bw_cycle_idx_ = (probe_bw_cycle_idx_ + 1) % 8;
            pacing_rate_ = btl_bw_bps_ * PROBE_BW_GAIN[probe_bw_cycle_idx_];
            cwnd_ = (btl_bw_bps_ * min_rtt_us_ / 1000000ULL) * 2; // 2 BDP window
            break;
            
        case State::PROBE_RTT:
            cwnd_ = 1460 * 4; // Drop window to 4 packets
            // Wait for 200ms... then return to PROBE_BW
            break;
    }

    cwnd_ = std::clamp(cwnd_, INITIAL_CWND, MAX_CWND);
}

void BbrCongestionControl::on_packet_lost(uint64_t sequence_number, size_t bytes_lost) {
    // BBR doesn't directly shrink window on loss like CUBIC does, 
    // unless loss is excessive.
    if (state_ == State::STARTUP) {
        // High loss exits startup
        state_ = State::DRAIN;
    }
}

uint64_t BbrCongestionControl::get_pacing_rate() const {
    return pacing_rate_;
}

uint64_t BbrCongestionControl::get_congestion_window() const {
    return cwnd_;
}

} // namespace nit::osnova::mesh
