#pragma once

#include <string_view>
#include <vector>
#include <memory>
#include <expected>
#include <functional>
#include <span>
#include <cstdint>
// Forward declarations for ASIO to avoid heavy include in headers
namespace asio {
    class io_context;
    namespace ip {
        class udp;
    }
}

namespace nit::quic {

enum class StreamType : uint8_t {
    Control = 0,
    Media = 1,
    FileTransfer = 2,
    LedgerSync = 3
};

struct QuicConfig {
    std::string bind_address;
    uint16_t bind_port;
    std::string cert_file;
    std::string key_file;
    uint32_t idle_timeout_ms = 30000;
    uint32_t max_udp_payload_size = 1200;
};

/**
 * @brief Zero-cost interface over ngtcp2/msquic for the L1 Mainline network.
 * Handles UDP socket polling via ASIO and multiplexes QUIC streams.
 * 
 * Memory bounds are strictly defined. No dynamic allocations per packet.
 */
class QuicEngine {
public:
    explicit QuicEngine(std::shared_ptr<asio::io_context> io_ctx);
    ~QuicEngine();

    // No copy/move
    QuicEngine(const QuicEngine&) = delete;
    QuicEngine& operator=(const QuicEngine&) = delete;

    [[nodiscard]] std::expected<void, std::string_view> start_server(const QuicConfig& config);
    [[nodiscard]] std::expected<void, std::string_view> connect_client(const std::string& host, uint16_t port);

    // Stream Management
    [[nodiscard]] std::expected<uint64_t, std::string_view> open_bidi_stream(StreamType type);
    
    // Asynchronous send with zero-copy semantic where possible
    void async_send(uint64_t stream_id, std::span<const std::byte> payload, std::function<void(bool)> completion_cb);
    
    // Callback Registration
    using StreamDataCallback = std::function<void(uint64_t stream_id, std::span<const std::byte> data)>;
    void set_data_callback(StreamDataCallback cb);

    using ConnectionCallback = std::function<void(bool is_connected, std::string_view remote_ip)>;
    void set_connection_callback(ConnectionCallback cb);

    // Multipath/Migration Triggers
    void force_migration_to_path(const std::string& host, uint16_t port);
    void reset_congestion_window() noexcept;

private:
    struct Impl;
    std::unique_ptr<Impl> pimpl_;
};

} // namespace nit::quic
