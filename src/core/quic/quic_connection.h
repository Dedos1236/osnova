#pragma once

#include <vector>
#include <cstdint>
#include <expected>
#include <string_view>
#include <span>
#include <memory>
#include <asio.hpp>

namespace nit::quic {

/**
 * @brief Represents a single QUIC connection over L1 Mainline.
 * Built for high-throughput, integrating with ASIO's asynchronous model.
 * Zero-copy parsing of QUIC Short Header packets.
 */
class QuicConnection {
public:
    QuicConnection(std::shared_ptr<asio::io_context> io_ctx, uint64_t connection_id);
    ~QuicConnection();

    // Disable copy/move
    QuicConnection(const QuicConnection&) = delete;
    QuicConnection& operator=(const QuicConnection&) = delete;

    /**
     * @brief Processes an incoming raw UDP datagram.
     */
    void process_udp_datagram(std::span<const uint8_t> datagram, const asio::ip::udp::endpoint& remote_ep);

    /**
     * @brief Queue a QUIC stream frame for transmission.
     */
    void queue_stream_frame(uint64_t stream_id, std::span<const uint8_t> data, bool fin);

    /**
     * @brief Flush pending frames into UDP packets and transmit via the provided socket.
     */
    void flush_transmission(asio::ip::udp::socket& socket, const asio::ip::udp::endpoint& remote_ep);

    uint64_t get_connection_id() const noexcept;

private:
    struct Impl;
    std::unique_ptr<Impl> pimpl_;
};

} // namespace nit::quic
