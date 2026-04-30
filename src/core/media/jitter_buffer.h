#pragma once

#include <vector>
#include <cstdint>
#include <mutex>
#include <map>
#include <optional> 

namespace nit::osnova::media {

/**
 * @brief Adaptive Jitter Buffer.
 * Crucial for smooth audio/video playback during real-time UDP streams.
 * Handles out-of-order packets, duplicates, and dynamically scales buffer depth 
 * based on network latency variance (jitter).
 */
class JitterBuffer {
public:
    struct Packet {
        uint16_t sequence_number;
        uint32_t timestamp;
        std::vector<uint8_t> payload;
        bool is_marker;
    };

    explicit JitterBuffer(uint32_t clock_rate, size_t initial_delay_ms = 50);
    ~JitterBuffer();

    /**
     * @brief Insert a received RTP packet into the jitter buffer.
     */
    void push(const Packet& packet);

    /**
     * @brief Pop the next contiguous packet ready for decoding.
     */
    std::optional<Packet> pop();

    /**
     * @brief Internal tick to recalculate dynamic delay bounds based on recent packet arrival times.
     */
    void update_jitter_estimation(uint32_t transit_time_ms);

private:
    uint32_t clock_rate_;
    size_t target_delay_ms_;
    size_t current_jitter_ms_ = 0;

    std::mutex mtx_;
    std::map<uint16_t, Packet> buffer_;
    uint16_t next_seq_to_pop_ = 0;
    bool is_initialized_ = false;
};

} // namespace nit::osnova::media
