#include "kcp_session.h"
#include <cstring>
#include <algorithm>

namespace nit::osnova::net {

namespace {
    static inline uint32_t _ibound_(uint32_t lower, uint32_t middle, uint32_t upper) {
        return std::min(std::max(lower, middle), upper);
    }
    static inline int _itimediff(uint32_t later, uint32_t earlier) {
        return ((int32_t)(later - earlier));
    }
    
    constexpr uint32_t IKCP_RTO_NDL = 30;
    constexpr uint32_t IKCP_RTO_MIN = 100;
    constexpr uint32_t IKCP_RTO_DEF = 200;
    constexpr uint32_t IKCP_RTO_MAX = 60000;
    
    constexpr uint32_t IKCP_CMD_PUSH = 81;
    constexpr uint32_t IKCP_CMD_ACK  = 82;
    constexpr uint32_t IKCP_CMD_WASK = 83;
    constexpr uint32_t IKCP_CMD_WINS = 84;
    
    constexpr uint32_t IKCP_WND_SND = 32;
    constexpr uint32_t IKCP_WND_RCV = 128;
    constexpr uint32_t IKCP_MTU_DEF = 1400;
    constexpr uint32_t IKCP_MSS_DEF = IKCP_MTU_DEF - 24;
    constexpr uint32_t IKCP_DEADLINK = 20;

    void encode8u(uint8_t* p, uint8_t c) { p[0] = c; }
    void encode16u(uint8_t* p, uint16_t w) {
        p[0] = (uint8_t)(w >> 0);
        p[1] = (uint8_t)(w >> 8);
    }
    void encode32u(uint8_t* p, uint32_t l) {
        p[0] = (uint8_t)(l >> 0);
        p[1] = (uint8_t)(l >> 8);
        p[2] = (uint8_t)(l >> 16);
        p[3] = (uint8_t)(l >> 24);
    }

    const uint8_t* decode8u(const uint8_t* p, uint8_t* c) { *c = p[0]; return p + 1; }
    const uint8_t* decode16u(const uint8_t* p, uint16_t* w) {
        *w = (p[0]) | ((uint16_t)p[1] << 8); return p + 2;
    }
    const uint8_t* decode32u(const uint8_t* p, uint32_t* l) {
        *l = ((uint32_t)p[0]) | ((uint32_t)p[1] << 8) | ((uint32_t)p[2] << 16) | ((uint32_t)p[3] << 24);
        return p + 4;
    }
}

KcpSession::KcpSession(uint32_t conv, void* user) 
    : conv_(conv), user_(user) 
{
    snd_wnd_ = IKCP_WND_SND;
    rcv_wnd_ = IKCP_WND_RCV;
    rmt_wnd_ = IKCP_WND_RCV;
    mtu_ = IKCP_MTU_DEF;
    mss_ = mtu_ - 24;
    buffer_.resize((mtu_ + 24) * 3);
    
    rx_rto_ = IKCP_RTO_DEF;
    rx_minrto_ = IKCP_RTO_MIN;
    interval_ = 100;
    ts_flush_ = IKCP_RTO_DEF;
    ssthresh_ = IKCP_WND_SND;
    dead_link_ = IKCP_DEADLINK;
    
    nodelay_ = 0;
    updated_ = 0;
    fastresend_ = 0;
    nocwnd_ = 0;
    
    snd_una_ = 0;
    snd_nxt_ = 0;
    rcv_nxt_ = 0;
    cwnd_ = 0;
    probe_ = 0;
    incr_ = 0;
    ts_probe_ = 0;
    probe_wait_ = 0;
    rx_rttval_ = 0;
    rx_srtt_ = 0;
    state_ = 0;
    current_ = 0;
    xmit_ = 0;
}

KcpSession::~KcpSession() = default;

KcpSession::Segment KcpSession::create_segment(size_t size) {
    Segment seg;
    seg.data.resize(size);
    return seg;
}

void KcpSession::set_output(OutputCallback cb) {
    output_ = std::move(cb);
}

void KcpSession::set_nodelay(int nodelay, int interval, int resend, int nc) {
    if (nodelay >= 0) {
        nodelay_ = nodelay;
        if (nodelay) rx_minrto_ = IKCP_RTO_NDL;
        else rx_minrto_ = IKCP_RTO_MIN;
    }
    if (interval >= 0) {
        interval_ = interval;
        if (interval_ > 5000) interval_ = 5000;
        else if (interval_ < 10) interval_ = 10;
    }
    if (resend >= 0) fastresend_ = resend;
    if (nc >= 0) nocwnd_ = nc;
}

void KcpSession::set_wndsize(int sndwnd, int rcvwnd) {
    if (sndwnd > 0) snd_wnd_ = sndwnd;
    if (rcvwnd > 0) rcv_wnd_ = rcvwnd;
}

void KcpSession::set_mtu(int mtu) {
    if (mtu < 50 || mtu > 65535) return;
    mtu_ = mtu;
    mss_ = mtu_ - 24;
    buffer_.resize((mtu_ + 24) * 3);
}

int KcpSession::peek_size() const {
    if (rcv_queue_.empty()) return -1;
    auto it = rcv_queue_.begin();
    if (it->frg == 0) return it->data.size();
    if (rcv_queue_.size() < it->frg + 1) return -1;
    
    int length = 0;
    for (const auto& seg : rcv_queue_) {
        length += seg.data.size();
        if (seg.frg == 0) break;
    }
    return length;
}

int KcpSession::recv(std::span<uint8_t> buffer) {
    int peeksize = peek_size();
    if (peeksize < 0) return -1;
    if (buffer.size() < (size_t)peeksize) return -2;
    
    bool recover = rcv_queue_.size() >= rcv_wnd_;
    
    int len = 0;
    for (auto it = rcv_queue_.begin(); it != rcv_queue_.end();) {
        int fragment = it->frg;
        std::memcpy(buffer.data() + len, it->data.data(), it->data.size());
        len += it->data.size();
        it = rcv_queue_.erase(it);
        if (fragment == 0) break;
    }
    
    while (!rcv_buf_.empty()) {
        auto& seg = rcv_buf_.front();
        if (seg.sn == rcv_nxt_ && rcv_queue_.size() < rcv_wnd_) {
            rcv_queue_.push_back(std::move(seg));
            rcv_buf_.pop_front();
            rcv_nxt_++;
        } else break;
    }
    
    if (rcv_queue_.size() < rcv_wnd_ && recover) {
        probe_ |= 2; // Tell remote window size
    }
    return len;
}

int KcpSession::send(std::span<const uint8_t> buffer) {
    if (buffer.empty()) return -1;
    
    int count = (buffer.size() <= mss_) ? 1 : (buffer.size() + mss_ - 1) / mss_;
    if (count >= 255) return -2;
    if (count == 0) count = 1;
    
    int offset = 0;
    for (int i=0; i<count; ++i) {
        int size = (buffer.size() - offset > mss_) ? mss_ : (buffer.size() - offset);
        Segment seg = create_segment(size);
        std::memcpy(seg.data.data(), buffer.data() + offset, size);
        seg.frg = (count - i - 1);
        snd_queue_.push_back(std::move(seg));
        offset += size;
    }
    return 0;
}

void KcpSession::update_ack(int32_t rtt) {
    if (rx_srtt_ == 0) {
        rx_srtt_ = rtt;
        rx_rttval_ = rtt / 2;
    } else {
        int32_t delta = rtt - rx_srtt_;
        if (delta < 0) delta = -delta;
        rx_rttval_ = (3 * rx_rttval_ + delta) / 4;
        rx_srtt_ = (7 * rx_srtt_ + rtt) / 8;
        if (rx_srtt_ < 1) rx_srtt_ = 1;
    }
    uint32_t rto = rx_srtt_ + std::max((int)rx_rttval_ * 4, 8); // MAX / MIN
    rx_rto_ = _ibound_(rx_minrto_, rto, IKCP_RTO_MAX);
}

void KcpSession::shrink_buf() {
    if (!snd_buf_.empty()) snd_una_ = snd_buf_.front().sn;
    else snd_una_ = snd_nxt_;
}

void KcpSession::parse_ack(uint32_t sn) {
    if (_itimediff(sn, snd_una_) < 0 || _itimediff(sn, snd_nxt_) >= 0) return;
    for (auto it = snd_buf_.begin(); it != snd_buf_.end();) {
        if (sn == it->sn) {
            it = snd_buf_.erase(it);
            break;
        }
        if (_itimediff(sn, it->sn) < 0) break;
        ++it;
    }
}

void KcpSession::parse_una(uint32_t una) {
    for (auto it = snd_buf_.begin(); it != snd_buf_.end();) {
        if (_itimediff(una, it->sn) > 0) it = snd_buf_.erase(it);
        else break;
    }
}

void KcpSession::parse_fastack(uint32_t sn, uint32_t ts) {
    if (_itimediff(sn, snd_una_) < 0 || _itimediff(sn, snd_nxt_) >= 0) return;
    for (auto& seg : snd_buf_) {
        if (_itimediff(sn, seg.sn) < 0) break;
        else if (sn != seg.sn) {
            seg.fastack++;
        }
    }
}

int KcpSession::input(std::span<const uint8_t> data) {
    const uint8_t* p = data.data();
    uint32_t una = snd_una_;
    uint32_t maxack = 0, latest_ts = 0;
    int flag = 0;
    
    if (data.size() < 24) return -1;
    size_t offset = 0;
    
    while (true) {
        uint32_t conv, cmd, frg, wnd, ts, sn, una_recv, len;
        if (data.size() - offset < 24) break;
        
        p = decode32u(p, &conv);
        if (conv != conv_) return -1;
        p = decode8u(p, (uint8_t*)&cmd);
        p = decode8u(p, (uint8_t*)&frg);
        p = decode16u(p, (uint16_t*)&wnd);
        p = decode32u(p, &ts);
        p = decode32u(p, &sn);
        p = decode32u(p, &una_recv);
        p = decode32u(p, &len);
        offset += 24;
        
        if (data.size() - offset < len) return -2;
        
        rmt_wnd_ = wnd;
        parse_una(una_recv);
        shrink_buf();
        
        if (cmd == IKCP_CMD_ACK) {
            if (_itimediff(current_, ts) >= 0) {
                update_ack(_itimediff(current_, ts));
            }
            parse_ack(sn);
            shrink_buf();
            if (!flag) {
                flag = 1;
                maxack = sn;
                latest_ts = ts;
            } else {
                if (_itimediff(sn, maxack) > 0) {
                    maxack = sn;
                    latest_ts = ts;
                }
            }
        } else if (cmd == IKCP_CMD_PUSH) {
            if (_itimediff(sn, rcv_nxt_ + rcv_wnd_) < 0) {
                acklist_.push_back(sn);
                acklist_.push_back(ts);
                if (_itimediff(sn, rcv_nxt_) >= 0) {
                    Segment seg = create_segment(len);
                    seg.conv = conv; seg.cmd = cmd; seg.frg = frg; seg.wnd = wnd;
                    seg.ts = ts; seg.sn = sn; seg.una = una_recv;
                    std::memcpy(seg.data.data(), p, len);
                    
                    bool repeat = false;
                    for (auto it = rcv_buf_.rbegin(); it != rcv_buf_.rend(); ++it) {
                        if (it->sn == sn) { repeat = true; break; }
                        if (_itimediff(sn, it->sn) > 0) break;
                    }
                    if (!repeat) {
                        auto it = rcv_buf_.end();
                        while (it != rcv_buf_.begin()) {
                            --it;
                            if (_itimediff(sn, it->sn) > 0) {
                                ++it;
                                break;
                            }
                        }
                        rcv_buf_.insert(it, std::move(seg));
                    }
                }
            }
        } else if (cmd == IKCP_CMD_WASK) {
            probe_ |= 2;
        } else if (cmd == IKCP_CMD_WINS) {
            // Ignore
        }
        
        p += len;
        offset += len;
    }
    
    if (flag != 0) {
        parse_fastack(maxack, latest_ts);
    }
    
    if (_itimediff(snd_una_, una) > 0) {
        if (cwnd_ < rmt_wnd_) {
            uint32_t mss = mss_;
            if (cwnd_ < ssthresh_) {
                cwnd_++;
                incr_ += mss;
            } else {
                if (incr_ < mss) incr_ = mss;
                incr_ += (mss * mss) / incr_ + (mss / 16);
                if ((cwnd_ + 1) * mss <= incr_) cwnd_++;
            }
            if (cwnd_ > rmt_wnd_) {
                cwnd_ = rmt_wnd_;
                incr_ = rmt_wnd_ * mss;
            }
        }
    }
    return 0;
}

int KcpSession::encode_seg(uint8_t* ptr, const Segment& seg) {
    uint8_t* p = ptr;
    encode32u(p, seg.conv); p += 4;
    encode8u(p, (uint8_t)seg.cmd); p += 1;
    encode8u(p, (uint8_t)seg.frg); p += 1;
    encode16u(p, (uint16_t)seg.wnd); p += 2;
    encode32u(p, seg.ts); p += 4;
    encode32u(p, seg.sn); p += 4;
    encode32u(p, seg.una); p += 4;
    encode32u(p, seg.data.size()); p += 4;
    return p - ptr;
}

void KcpSession::flush() {
    uint32_t current = current_;
    int change = 0;
    int lost = 0;
    
    if (!updated_) return;
    
    Segment seg;
    seg.conv = conv_;
    seg.cmd = IKCP_CMD_ACK;
    seg.frg = 0;
    seg.wnd = std::max((int)rcv_wnd_ - (int)rcv_queue_.size(), 0);
    seg.una = rcv_nxt_;
    seg.sn = 0;
    seg.ts = 0;
    
    uint8_t* ptr = buffer_.data();
    size_t mem_offset = 0;
    
    // flush acks
    for (size_t i = 0; i < acklist_.size(); i += 2) {
        if (mem_offset + 24 > mtu_) {
            if (output_) output_(std::vector<uint8_t>(buffer_.begin(), buffer_.begin() + mem_offset), mem_offset);
            mem_offset = 0;
        }
        seg.sn = acklist_[i];
        seg.ts = acklist_[i+1];
        mem_offset += encode_seg(ptr + mem_offset, seg);
    }
    acklist_.clear();
    
    // probe window size
    if (rmt_wnd_ == 0) {
        if (probe_wait_ == 0) {
            probe_wait_ = IKCP_RTO_DEF;
            ts_probe_ = current + probe_wait_;
        } else {
            if (_itimediff(current, ts_probe_) >= 0) {
                if (probe_wait_ < IKCP_RTO_DEF) probe_wait_ = IKCP_RTO_DEF;
                probe_wait_ += probe_wait_ / 2;
                if (probe_wait_ > IKCP_RTO_MAX) probe_wait_ = IKCP_RTO_MAX;
                ts_probe_ = current + probe_wait_;
                probe_ |= 1;
            }
        }
    } else {
        ts_probe_ = 0;
        probe_wait_ = 0;
    }
    
    // flush window probing
    if (probe_ & 1) {
        seg.cmd = IKCP_CMD_WASK;
        if (mem_offset + 24 > mtu_) {
            if (output_) output_(std::vector<uint8_t>(buffer_.begin(), buffer_.begin() + mem_offset), mem_offset);
            mem_offset = 0;
        }
        mem_offset += encode_seg(ptr + mem_offset, seg);
    }
    
    // flush window telling
    if (probe_ & 2) {
        seg.cmd = IKCP_CMD_WINS;
        if (mem_offset + 24 > mtu_) {
            if (output_) output_(std::vector<uint8_t>(buffer_.begin(), buffer_.begin() + mem_offset), mem_offset);
            mem_offset = 0;
        }
        mem_offset += encode_seg(ptr + mem_offset, seg);
    }
    probe_ = 0;
    
    uint32_t cwnd = std::min(snd_wnd_, rmt_wnd_);
    if (!nocwnd_) cwnd = std::min(cwnd_, cwnd);
    
    // push to snd_buf
    while (_itimediff(snd_nxt_, snd_una_ + cwnd) < 0) {
        if (snd_queue_.empty()) break;
        Segment newseg = std::move(snd_queue_.front());
        snd_queue_.pop_front();
        
        newseg.conv = conv_;
        newseg.cmd = IKCP_CMD_PUSH;
        newseg.wnd = seg.wnd;
        newseg.ts = current;
        newseg.sn = snd_nxt_++;
        newseg.una = rcv_nxt_;
        newseg.resendts = current;
        newseg.rto = rx_rto_;
        newseg.fastack = 0;
        newseg.xmit = 0;
        snd_buf_.push_back(std::move(newseg));
    }
    
    // compute resend rto
    uint32_t resent = fastresend_ > 0 ? fastresend_ : 0xffffffff;
    uint32_t rtomin = (nodelay_ == 0) ? (rx_rto_ >> 3) : 0;
    
    // flush data segments
    for (auto& s : snd_buf_) {
        bool needsend = false;
        if (s.xmit == 0) {
            needsend = true;
            s.xmit++;
            s.rto = rx_rto_;
            s.resendts = current + s.rto + rtomin;
        } else if (_itimediff(current, s.resendts) >= 0) {
            needsend = true;
            s.xmit++;
            xmit_++;
            if (nodelay_ == 0) s.rto += std::max(s.rto, (uint32_t)10000);
            else s.rto += (s.rto / 2); // 1.5 timeout
            s.resendts = current + s.rto;
            lost = 1;
        } else if (s.fastack >= resent) {
            if ((int)s.xmit <= 5 || s.fastack > 2) {
                needsend = true;
                s.xmit++;
                s.fastack = 0;
                s.resendts = current + s.rto;
                change++;
            }
        }
        
        if (needsend) {
            s.ts = current;
            s.wnd = seg.wnd;
            s.una = rcv_nxt_;
            
            size_t seg_size = 24 + s.data.size();
            if (mem_offset + seg_size > mtu_) {
                if (output_) output_(std::vector<uint8_t>(buffer_.begin(), buffer_.begin() + mem_offset), mem_offset);
                mem_offset = 0;
            }
            mem_offset += encode_seg(ptr + mem_offset, s);
            if (!s.data.empty()) {
                std::memcpy(ptr + mem_offset, s.data.data(), s.data.size());
                mem_offset += s.data.size();
            }
            if (s.xmit >= dead_link_) state_ = 0xFFFFFFFF;
        }
    }
    
    // flush remains
    if (mem_offset > 0) {
        if (output_) output_(std::vector<uint8_t>(buffer_.begin(), buffer_.begin() + mem_offset), mem_offset);
    }
    
    // update cwnd
    if (change) {
        uint32_t inflight = snd_nxt_ - snd_una_;
        ssthresh_ = inflight / 2;
        if (ssthresh_ < IKCP_WND_SND) ssthresh_ = IKCP_WND_SND;
        cwnd_ = ssthresh_ + resent;
        incr_ = cwnd_ * mss_;
    }
    if (lost) {
        ssthresh_ = cwnd_ / 2;
        if (ssthresh_ < IKCP_WND_SND) ssthresh_ = IKCP_WND_SND;
        cwnd_ = 1;
        incr_ = mss_;
    }
    if (cwnd_ < 1) {
        cwnd_ = 1;
        incr_ = mss_;
    }
}

void KcpSession::update(uint32_t current_time_ms) {
    current_ = current_time_ms;
    if (!updated_) {
        updated_ = 1;
        ts_flush_ = current_;
    }
    
    int32_t slap = _itimediff(current_, ts_flush_);
    if (slap >= 10000 || slap < -10000) {
        ts_flush_ = current_;
        slap = 0;
    }
    
    if (slap >= 0) {
        ts_flush_ += interval_;
        if (_itimediff(current_, ts_flush_) >= 0) {
            ts_flush_ = current_ + interval_;
        }
        flush();
    }
}

int KcpSession::wait_snd() const {
    return snd_buf_.size() + snd_queue_.size();
}

} // namespace nit::osnova::net
