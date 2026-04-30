#pragma once

#include <cstdint>
#include <vector>
#include <memory>
#include <map>
#include <string>
#include <functional>

namespace nit::osnova::net {

/**
 * @brief Connection Multiplexer.
 * Allows multiplexing hundreds of logical streams over a single underlying transport 
 * (like TCP or UDP via QUIC module). Crucial for MTProto-like connection pooling 
 * and advanced high-throughput pipelining.
 */
class Multiplexer {
public:
    using StreamId = uint32_t;
    using DataCallback = std::function<void(StreamId, const std::vector<uint8_t>&)>;

    Multiplexer();
    ~Multiplexer();

    /**
     * @brief Create a new logical stream.
     */
    StreamId create_stream();

    /**
     * @brief Send data on a specific logical stream.
     * Muxes the data into frames and pushes to the underlying transport sender.
     */
    bool send(StreamId sid, const std::vector<uint8_t>& payload);

    /**
     * @brief Feed raw data from the underlying transport into the multiplexer.
     * It will de-mux, reassemble, and fire the DataCallback for the correct stream.
     */
    void receive_transport_data(const std::vector<uint8_t>& raw_data);

    void set_transport_sender(std::function<void(const std::vector<uint8_t>&)> sender);
    void set_data_callback(DataCallback cb);

private:
    struct Impl;
    std::unique_ptr<Impl> impl_;
};

} // namespace nit::osnova::net
