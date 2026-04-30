#include "jitter_buffer.h"
#include <algorithm>

namespace nit::osnova::media {

JitterBuffer::JitterBuffer(uint32_t clock_rate, size_t initial_delay_ms)
    : clock_rate_(clock_rate), target_delay_ms_(initial_delay_ms) {}

JitterBuffer::~JitterBuffer() = default;

void JitterBuffer::push(const Packet& packet) {
    std::lock_guard<std::mutex> lock(mtx_);

    if (!is_initialized_) {
        next_seq_to_pop_ = packet.sequence_number;
        is_initialized_ = true;
    }

    // Calculate correct distance handling 16-bit sequence number wrap-around
    int16_t diff = static_cast<int16_t>(packet.sequence_number - next_seq_to_pop_);
    
    // If the packet is too old (late arrival), discard it
    if (diff < -500) {
        return; // Discard completely out-of-order or duplicate packets that are too old
    }

    // Insert packet into sorted map
    buffer_[packet.sequence_number] = packet;
    
    // Dynamic purge based on buffer depth to enforce max jitter latency constraint
    // Limit to max 500 packets (typically covering ~10 seconds of 50pps audio)
    while (buffer_.size() > 500) {
        // Discard oldest packets
        auto oldest = buffer_.begin();
        // Adjust the expected sequence number if we are bypassing packets
        int16_t distance = static_cast<int16_t>(oldest->first - next_seq_to_pop_);
        if (distance >= 0) {
            next_seq_to_pop_ = oldest->first + 1;
        }
        buffer_.erase(oldest);
    }
}

std::optional<JitterBuffer::Packet> JitterBuffer::pop() {
    std::lock_guard<std::mutex> lock(mtx_);
    if (buffer_.empty()) return std::nullopt;

    auto it = buffer_.find(next_seq_to_pop_);
    if (it != buffer_.end()) {
        Packet p = it->second;
        buffer_.erase(it);
        next_seq_to_pop_++;
        return p;
    }

    // Simple conceal: If missing, check if we waited too long
    // Here we just skip to the next available if gap is large
    if (!buffer_.empty()) {
        auto first_avail = buffer_.begin();
        int16_t gap = first_avail->first - next_seq_to_pop_;
        if (gap > 5) { // Threshold for skipping
            Packet p = first_avail->second;
            next_seq_to_pop_ = first_avail->first + 1;
            buffer_.erase(first_avail);
            return p;
        }
    }

    return std::nullopt;
}

void JitterBuffer::update_jitter_estimation(uint32_t transit_time_ms) {
    std::lock_guard<std::mutex> lock(mtx_);
    // EWMA (Exponential Weighted Moving Average) for jitter
    int32_t delta = static_cast<int32_t>(transit_time_ms) - static_cast<int32_t>(target_delay_ms_);
    if (delta < 0) delta = -delta;
    
    current_jitter_ms_ = current_jitter_ms_ + ((delta - current_jitter_ms_) / 16);
    target_delay_ms_ = std::max<size_t>(20, std::min<size_t>(500, current_jitter_ms_ * 2));
}

} // namespace nit::osnova::media
