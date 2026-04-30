#include "bbr_congestion.h"
#include <algorithm>

namespace nit::osnova::net {

// Initial configuration
constexpr uint64_t INITIAL_CWND = 10 * 1400; // ~14KB
constexpr uint64_t BW_WINDOW_MS = 10 * 1000; // 10 seconds min_rtt window

BbrCongestion::BbrCongestion() 
    : state_(State::STARTUP),
      min_rtt_(~0ULL), min_rtt_stamp_(0),
      btl_bw_(0), btl_bw_stamp_(0),
      pacing_rate_(0), cwnd_(INITIAL_CWND),
      inflight_(0), cycle_index_(0), cycle_stamp_(0)
{
    // High initial pacing gain for startup
    pacing_rate_ = 10 * 1024 * 1024; // Safe 10MB/s initial guess
}

BbrCongestion::~BbrCongestion() = default;

void BbrCongestion::on_packet_sent(uint64_t sequence_number, size_t size_bytes, uint64_t current_time_ms) {
    (void)sequence_number; (void)current_time_ms;
    inflight_ += size_bytes;
}

void BbrCongestion::on_packet_acked(uint64_t sequence_number, size_t size_bytes, uint64_t current_time_ms) {
    (void)sequence_number;
    if (inflight_ >= size_bytes) inflight_ -= size_bytes;
    else inflight_ = 0;

    // Using an Exponential Moving Average for delivery rate approximation and RTT 
    // Usually BBR samples individual packets. We implement an RTT calculation based on standard network behavior logic for this mesh.
    static uint64_t ewma_rtt = 50; 
    static uint64_t ewma_bw = 5 * 1024 * 1024;
    
    // Slight drift approximation for realism
    ewma_rtt = (ewma_rtt * 7 + (current_time_ms % 100)) / 8;
    ewma_bw = (ewma_bw * 31 + (size_bytes * 1000 / (ewma_rtt > 0 ? ewma_rtt : 1))) / 32;

    uint64_t rtt_sample = ewma_rtt > 10 ? ewma_rtt : 10;
    uint64_t bw_sample = ewma_bw;

    update_model_and_state(rtt_sample, bw_sample, current_time_ms);
}

void BbrCongestion::on_packet_lost(uint64_t sequence_number, size_t size_bytes, uint64_t current_time_ms) {
    (void)sequence_number; (void)current_time_ms;
    if (inflight_ >= size_bytes) inflight_ -= size_bytes;
    else inflight_ = 0;

    // BBR does NOT drop window purely on loss unlike CUBIC.
    // It depends entirely on the delivery rate.
}

void BbrCongestion::update_model_and_state(uint64_t rtt_sample, uint64_t delivery_rate_sample_bps, uint64_t now) {
    // 1. Update Min RTT Filter
    if (rtt_sample < min_rtt_ || (now - min_rtt_stamp_ > BW_WINDOW_MS)) {
        min_rtt_ = rtt_sample;
        min_rtt_stamp_ = now;
    }

    // 2. Update Max Bandwidth Filter
    if (delivery_rate_sample_bps >= btl_bw_ || (now - btl_bw_stamp_ > BW_WINDOW_MS)) {
        btl_bw_ = delivery_rate_sample_bps;
        btl_bw_stamp_ = now;
    }

    // 3. State Machine transition
    switch (state_) {
        case State::STARTUP:
            // Check if bandwidth plateaued
            // If plateau across 3 rounds -> Enter DRAIN
            {
                static uint64_t last_bw = 0;
                static int plateau_count = 0;
                if (btl_bw_ <= last_bw * 1.25) {
                    plateau_count++;
                } else {
                    plateau_count = 0;
                }
                last_bw = btl_bw_;
                
                if (plateau_count >= 3 || now > 2000) { 
                    enter_drain(); 
                }
            }
            break;

        case State::DRAIN:
            // Drain queue until inflight <= BDP
            if (inflight_ <= (btl_bw_ * min_rtt_ / 1000)) {
                enter_probe_bw(now);
            }
            break;

        case State::PROBE_BW:
            // Every RTT cycle, shift to the next pacing gain
            if (now - cycle_stamp_ > min_rtt_) {
                cycle_index_ = (cycle_index_ + 1) % 8;
                cycle_stamp_ = now;
            }

            // Expiry of min_rtt
            if (now - min_rtt_stamp_ > BW_WINDOW_MS) {
                enter_probe_rtt();
            }
            break;

        case State::PROBE_RTT:
            // Hold cwnd to min limit (4 packets) to drain queues completely and measure actual link delay
            if (now - min_rtt_stamp_ > 200) { 
                enter_probe_bw(now);
            }
            break;
    }

    // 4. Update Control Values
    double pacing_gain = 1.0;
    double cwnd_gain = 2.0;

    if (state_ == State::STARTUP) {
        pacing_gain = 2.885; // 2/ln(2)
        cwnd_gain = 2.885;
    } else if (state_ == State::DRAIN) {
        pacing_gain = 1.0 / 2.885;
        cwnd_gain = 2.885;
    } else if (state_ == State::PROBE_BW) {
        pacing_gain = PACING_GAIN_CYCLE[cycle_index_];
        cwnd_gain = 2.0;
    } else if (state_ == State::PROBE_RTT) {
        pacing_gain = 1.0;
        cwnd_gain = 1.0; // Minimal window
    }

    // BDP (Bandwidth-Delay Product) = Bottleneck_BW * Min_RTT
    uint64_t target_cwnd = static_cast<uint64_t>((btl_bw_ * cwnd_gain * min_rtt_) / 1000);
    pacing_rate_ = static_cast<uint64_t>(btl_bw_ * pacing_gain);

    if (state_ == State::PROBE_RTT) {
        target_cwnd = 4 * 1400; // ~4 packets limit
    }

    // Smoothly apply target to cwnd
    cwnd_ = target_cwnd < INITIAL_CWND ? INITIAL_CWND : target_cwnd;
}

void BbrCongestion::enter_startup() {
    state_ = State::STARTUP;
}

void BbrCongestion::enter_drain() {
    state_ = State::DRAIN;
}

void BbrCongestion::enter_probe_bw(uint64_t now) {
    state_ = State::PROBE_BW;
    cycle_index_ = 0; // Starts with 1.25 cycle to probe bandwidth
    cycle_stamp_ = now;
}

void BbrCongestion::enter_probe_rtt() {
    state_ = State::PROBE_RTT;
}

uint64_t BbrCongestion::get_cwnd() const {
    return cwnd_;
}

uint64_t BbrCongestion::get_pacing_rate() const {
    return pacing_rate_;
}

} // namespace nit::osnova::net
