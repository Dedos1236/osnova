#pragma once

#include <vector>
#include <string>
#include <cstdint>
#include <memory>
#include <functional>

namespace nit::osnova::net {

/**
 * @brief QUIC Session Architecture.
 * Next-generation transport based heavily on UDP, bringing ALPN, 
 * 0-RTT handshakes, forward secrecy, and stream multiplexing into a single cohesive layer.
 * Massively minimizes connection latency for high-speed protocol networking.
 */
class QuicSession {
public:
    enum class State {
        HANDSHAKING,
        ESTABLISHED,
        CLOSED
    };

    QuicSession();
    ~QuicSession();

    /**
     * @brief Initiates 0-RTT/1-RTT handshake if client.
     */
    void connect(const std::string& host, uint16_t port);

    /**
     * @brief Accepts a connection if server.
     */
    void accept();

    /**
     * @brief Process an incoming UDP datagram packet.
     */
    void process_datagram(const std::vector<uint8_t>& datagram);

    /**
     * @brief Extract raw datagrams ready to be transmitted over the physical UDP socket.
     */
    std::vector<std::vector<uint8_t>> flush_transmission_queue();

    /**
     * @brief Transmit application data reliably over a reliable stream.
     */
    void send_stream_data(uint32_t stream_id, const std::vector<uint8_t>& data);

    State get_state() const;

private:
    struct Impl;
    std::unique_ptr<Impl> impl_;
};

} // namespace nit::osnova::net
