#include "multiplexer.h"
#include <mutex>
#include <cstring>
#include <arpa/inet.h>

namespace nit::osnova::net {

struct Multiplexer::Impl {
    std::function<void(const std::vector<uint8_t>&)> transport_sender;
    DataCallback ds_cb;

    std::mutex mtx;
    StreamId next_stream_id = 1;
    
    // De-mux state tracking buffer limits and reassembly
    std::map<StreamId, std::vector<uint8_t>> recv_buffers;
    std::vector<uint8_t> parsing_buffer;
};

Multiplexer::Multiplexer() : impl_(std::make_unique<Impl>()) {}
Multiplexer::~Multiplexer() = default;

Multiplexer::StreamId Multiplexer::create_stream() {
    std::lock_guard<std::mutex> lock(impl_->mtx);
    StreamId sid = impl_->next_stream_id;
    impl_->next_stream_id += 2; // Client streams are odd
    return sid;
}

bool Multiplexer::send(StreamId sid, const std::vector<uint8_t>& payload) {
    if (!impl_->transport_sender) return false;

    // Frame layout: StreamId (4) | Len (4) | Payload
    std::vector<uint8_t> frame;
    frame.reserve(8 + payload.size());

    uint32_t net_sid = htonl(sid);
    uint32_t net_len = htonl(static_cast<uint32_t>(payload.size()));

    frame.insert(frame.end(), reinterpret_cast<uint8_t*>(&net_sid), reinterpret_cast<uint8_t*>(&net_sid) + 4);
    frame.insert(frame.end(), reinterpret_cast<uint8_t*>(&net_len), reinterpret_cast<uint8_t*>(&net_len) + 4);
    frame.insert(frame.end(), payload.begin(), payload.end());

    impl_->transport_sender(frame);
    return true;
}

void Multiplexer::receive_transport_data(const std::vector<uint8_t>& raw_data) {
    std::lock_guard<std::mutex> lock(impl_->mtx);
    impl_->parsing_buffer.insert(impl_->parsing_buffer.end(), raw_data.begin(), raw_data.end());

    while (impl_->parsing_buffer.size() >= 8) {
        uint32_t net_sid, net_len;
        std::memcpy(&net_sid, &impl_->parsing_buffer[0], 4);
        std::memcpy(&net_len, &impl_->parsing_buffer[4], 4);
        
        StreamId sid = ntohl(net_sid);
        uint32_t len = ntohl(net_len);

        if (impl_->parsing_buffer.size() < 8 + len) {
            break; // Need more data
        }

        std::vector<uint8_t> payload(impl_->parsing_buffer.begin() + 8, impl_->parsing_buffer.begin() + 8 + len);
        impl_->parsing_buffer.erase(impl_->parsing_buffer.begin(), impl_->parsing_buffer.begin() + 8 + len);

        if (impl_->ds_cb) {
            impl_->ds_cb(sid, payload);
        }
    }
}

void Multiplexer::set_transport_sender(std::function<void(const std::vector<uint8_t>&)> sender) {
    std::lock_guard<std::mutex> lock(impl_->mtx);
    impl_->transport_sender = std::move(sender);
}

void Multiplexer::set_data_callback(DataCallback cb) {
    std::lock_guard<std::mutex> lock(impl_->mtx);
    impl_->ds_cb = std::move(cb);
}

} // namespace nit::osnova::net
