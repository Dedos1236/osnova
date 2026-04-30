#pragma once

#include <string>
#include <vector>
#include <unordered_map>
#include <unordered_set>
#include <functional>
#include <cstdint>
#include <memory>
#include <chrono>

namespace nit::osnova::mesh {

struct GossipMessage {
    std::string msg_id;
    std::string topic;
    std::string source_peer_id;
    std::vector<uint8_t> data;
    uint64_t sequence_number;
};

/**
 * @brief GossipSub protocol implementation (similar to libp2p pubsub).
 * Provides highly scalable, robust pub/sub messaging for the OSNOVA mesh network.
 * Combines full-message mesh delivery with metadata-only gossip to peers.
 */
class GossipSub {
public:
    struct Config {
        int d = 6;       // Target degree
        int d_low = 4;   // Minimum degree
        int d_high = 12; // Maximum degree
        int d_lazy = 6;  // Gossip emission degree
        int heartbeat_interval_ms = 1000;
        int max_mcache_len = 5; // Message cache history length
    };

    explicit GossipSub(std::string local_peer_id, Config config = Config());
    ~GossipSub();

    void join_topic(const std::string& topic);
    void leave_topic(const std::string& topic);

    void publish(const std::string& topic, const std::vector<uint8_t>& data);

    // Callbacks
    using MessageCallback = std::function<void(const GossipMessage&)>;
    void set_message_callback(MessageCallback cb);

    using SendCallback = std::function<void(const std::string& peer_id, const std::vector<uint8_t>& raw_data)>;
    void set_send_callback(SendCallback cb);

    // Incoming events
    void on_peer_connected(const std::string& peer_id);
    void on_peer_disconnected(const std::string& peer_id);
    void on_message_received(const std::string& sender_peer_id, const std::vector<uint8_t>& raw_data);

    void tick_heartbeat();

private:
    struct Impl;
    std::unique_ptr<Impl> pimpl_;
};

} // namespace nit::osnova::mesh
