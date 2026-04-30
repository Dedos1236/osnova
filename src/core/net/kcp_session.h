#pragma once

#include <vector>
#include <cstdint>
#include <span>
#include <map>
#include <list>
#include <functional>

namespace nit::osnova::net {

/**
 * @brief OSNOVA KCP (Reliable UDP) implementation.
 * Provides a fast, reliable ARQ protocol mapped over UDP.
 * Based on the KCP ARQ protocol, prioritizing low latency over high throughput
 * for game-state and RTP streams.
 */
class KcpSession {
public:
    using OutputCallback = std::function<void(const std::vector<uint8_t>&, int)>; // data, length

    KcpSession(uint32_t conv, void* user);
    ~KcpSession();

    // Configuration
    void set_nodelay(int nodelay, int interval, int resend, int nc);
    void set_wndsize(int sndwnd, int rcvwnd);
    void set_mtu(int mtu);

    // I/O
    int send(std::span<const uint8_t> buffer);
    int recv(std::span<uint8_t> buffer);
    
    // Core loop
    void update(uint32_t current_time_ms);
    int input(std::span<const uint8_t> data);
    
    void set_output(OutputCallback cb);

    // Metrics
    int peek_size() const;
    int wait_snd() const;

private:
    struct Segment {
        uint32_t conv = 0;
        uint32_t cmd = 0;
        uint32_t frg = 0;
        uint32_t wnd = 0;
        uint32_t ts = 0;
        uint32_t sn = 0;
        uint32_t una = 0;
        uint32_t rto = 0;
        uint32_t xmit = 0;
        uint32_t resendts = 0;
        uint32_t fastack = 0;
        bool acked = false;
        std::vector<uint8_t> data;
    };

    uint32_t conv_;
    uint32_t mtu_;
    uint32_t mss_;
    uint32_t state_;
    uint32_t snd_una_;
    uint32_t snd_nxt_;
    uint32_t rcv_nxt_;

    uint32_t ssthresh_;
    int32_t rx_rttval_;
    int32_t rx_srtt_;
    int32_t rx_rto_;
    int32_t rx_minrto_;

    uint32_t snd_wnd_;
    uint32_t rcv_wnd_;
    uint32_t rmt_wnd_;
    uint32_t cwnd_;
    uint32_t probe_;

    uint32_t current_;
    uint32_t interval_;
    uint32_t ts_flush_;
    uint32_t xmit_;

    int nodelay_;
    int updated_;
    uint32_t ts_probe_;
    uint32_t probe_wait_;

    uint32_t dead_link_;
    uint32_t incr_;

    std::list<Segment> snd_queue_;
    std::list<Segment> rcv_queue_;
    std::list<Segment> snd_buf_;
    std::list<Segment> rcv_buf_;

    std::vector<uint32_t> acklist_;

    std::vector<uint8_t> buffer_;
    int fastresend_;
    int nocwnd_;
    void* user_;

    OutputCallback output_;

private:
    Segment create_segment(size_t size);
    void shrink_buf();
    void parse_ack(uint32_t sn);
    void parse_una(uint32_t una);
    void parse_fastack(uint32_t sn, uint32_t ts);
    void update_ack(int32_t rtt);
    
    int encode_seg(uint8_t* ptr, const Segment& seg);
    void flush();
};

} // namespace nit::osnova::net
