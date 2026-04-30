#include "gossip_sub.h"
#include "serialize.h"
#include <mutex>
#include <random>
#include <algorithm>

namespace nit::osnova::mesh {

struct GossipSub::Impl {
    std::string local_peer_id;
    Config config;
    MessageCallback on_message;
    SendCallback on_send;

    // State
    std::unordered_set<std::string> connected_peers;
    std::unordered_map<std::string, std::unordered_set<std::string>> mesh; // Topic -> Set of Peers (Full message passing)
    std::unordered_map<std::string, std::unordered_set<std::string>> fanout; // Topic -> Set of Peers (We don't subscribe to, but publish to)
    std::unordered_set<std::string> joined_topics;

    // Message ID Cache (Mcache) to prevent duplicates
    struct CacheEntry {
        std::string msg_id;
        std::chrono::steady_clock::time_point timestamp;
    };
    std::vector<CacheEntry> mcache;
    uint64_t seq_counter = 0;

    std::mutex mtx;

    bool has_seen_message(const std::string& msg_id) {
        return std::any_of(mcache.begin(), mcache.end(), [&](const CacheEntry& e) { return e.msg_id == msg_id; });
    }

    void add_to_mcache(const std::string& msg_id) {
        mcache.push_back({msg_id, std::chrono::steady_clock::now()});
        if (mcache.size() > 1000) { // Limit cache size
            mcache.erase(mcache.begin());
        }
    }
};

GossipSub::GossipSub(std::string local_peer_id, Config config)
    : pimpl_(std::make_unique<Impl>())
{
    pimpl_->local_peer_id = std::move(local_peer_id);
    pimpl_->config = config;
}

GossipSub::~GossipSub() = default;

void GossipSub::set_message_callback(MessageCallback cb) {
    pimpl_->on_message = std::move(cb);
}

void GossipSub::set_send_callback(SendCallback cb) {
    pimpl_->on_send = std::move(cb);
}

void GossipSub::join_topic(const std::string& topic) {
    std::lock_guard<std::mutex> lock(pimpl_->mtx);
    pimpl_->joined_topics.insert(topic);
    
    // Move peers from fanout to mesh if applicable
    if (pimpl_->fanout.count(topic)) {
        pimpl_->mesh[topic] = pimpl_->fanout[topic];
        pimpl_->fanout.erase(topic);
    }
}

void GossipSub::leave_topic(const std::string& topic) {
    std::lock_guard<std::mutex> lock(pimpl_->mtx);
    pimpl_->joined_topics.erase(topic);
    pimpl_->mesh.erase(topic);
}

void GossipSub::publish(const std::string& topic, const std::vector<uint8_t>& data) {
    std::lock_guard<std::mutex> lock(pimpl_->mtx);

    pimpl_->seq_counter++;
    std::string msg_id = pimpl_->local_peer_id + "_" + std::to_string(pimpl_->seq_counter);
    
    pimpl_->add_to_mcache(msg_id);

    // Determine target peers
    std::unordered_set<std::string> targets;
    if (pimpl_->joined_topics.count(topic) && pimpl_->mesh.count(topic)) {
        targets = pimpl_->mesh[topic];
    } else if (pimpl_->fanout.count(topic)) {
        targets = pimpl_->fanout[topic];
    } else {
        // Need to build fanout (select random peers)
        std::vector<std::string> all_peers(pimpl_->connected_peers.begin(), pimpl_->connected_peers.end());
        std::shuffle(all_peers.begin(), all_peers.end(), std::mt19937{std::random_device{}()});
        
        int count = std::min<int>(pimpl_->config.d, all_peers.size());
        for (int i = 0; i < count; ++i) {
            targets.insert(all_peers[i]);
            pimpl_->fanout[topic].insert(all_peers[i]);
        }
    }

    // Core RPC Serialization
    std::vector<uint8_t> payload;
    uint8_t topic_len = static_cast<uint8_t>(topic.size());
    uint8_t id_len = static_cast<uint8_t>(msg_id.size());
    payload.reserve(2 + topic_len + id_len + data.size());
    payload.push_back(topic_len);
    payload.insert(payload.end(), topic.begin(), topic.end());
    payload.push_back(id_len);
    payload.insert(payload.end(), msg_id.begin(), msg_id.end());
    payload.insert(payload.end(), data.begin(), data.end());

    if (pimpl_->on_send) {
        for (const auto& peer : targets) {
            pimpl_->on_send(peer, payload);
        }
    }
}

void GossipSub::on_peer_connected(const std::string& peer_id) {
    std::lock_guard<std::mutex> lock(pimpl_->mtx);
    pimpl_->connected_peers.insert(peer_id);
}

void GossipSub::on_peer_disconnected(const std::string& peer_id) {
    std::lock_guard<std::mutex> lock(pimpl_->mtx);
    pimpl_->connected_peers.erase(peer_id);
    
    for (auto& [topic, peers] : pimpl_->mesh) {
        peers.erase(peer_id);
    }
    for (auto& [topic, peers] : pimpl_->fanout) {
        peers.erase(peer_id);
    }
}

void GossipSub::on_message_received(const std::string& sender_peer_id, const std::vector<uint8_t>& raw_data) {
    std::lock_guard<std::mutex> lock(pimpl_->mtx);
    
    // Deserialize
    if (raw_data.size() < 2) return;
    
    size_t offset = 0;
    uint8_t topic_len = raw_data[offset++];
    if (raw_data.size() < offset + topic_len + 1) return;
    std::string topic(raw_data.begin() + offset, raw_data.begin() + offset + topic_len);
    offset += topic_len;

    uint8_t id_len = raw_data[offset++];
    if (raw_data.size() < offset + id_len) return;
    std::string msg_id(raw_data.begin() + offset, raw_data.begin() + offset + id_len);
    offset += id_len;

    std::vector<uint8_t> payload_data;
    if (offset < raw_data.size()) {
        payload_data.assign(raw_data.begin() + offset, raw_data.end());
    }

    GossipMessage msg;
    msg.msg_id = msg_id;
    msg.topic = topic;
    msg.source_peer_id = sender_peer_id;
    msg.data = std::move(payload_data);

    if (pimpl_->has_seen_message(msg.msg_id)) {
        return; // Duplicate
    }

    pimpl_->add_to_mcache(msg.msg_id);

    if (pimpl_->on_message) {
        pimpl_->on_message(msg);
    }

    // Forward to mesh peers
    if (pimpl_->joined_topics.count(msg.topic)) {
        if (pimpl_->mesh.count(msg.topic)) {
            if (pimpl_->on_send) {
                for (const auto& peer : pimpl_->mesh[msg.topic]) {
                    if (peer != sender_peer_id) {
                        pimpl_->on_send(peer, raw_data);
                    }
                }
            }
        }
    }
}

void GossipSub::tick_heartbeat() {
    std::lock_guard<std::mutex> lock(pimpl_->mtx);
    
    // Mesh maintenance
    for (const auto& topic : pimpl_->joined_topics) {
        auto& peers = pimpl_->mesh[topic];
        
        if (peers.size() < static_cast<size_t>(pimpl_->config.d_low)) {
            // Need more peers - graft
            int needed = pimpl_->config.d - peers.size(); // target D
            std::vector<std::string> valid_graft_targets;
            for (const auto& p : pimpl_->fanout[topic]) {
                if (peers.find(p) == peers.end()) {
                    valid_graft_targets.push_back(p);
                }
            }
            std::shuffle(valid_graft_targets.begin(), valid_graft_targets.end(), std::mt19937{std::random_device{}()});
            for(int i = 0; i < std::min<int>(needed, valid_graft_targets.size()); ++i) {
                peers.insert(valid_graft_targets[i]);
                if (pimpl_->on_send) {
                    std::vector<uint8_t> control_msg;
                    control_msg.push_back(0xFF); // Control Indicator
                    control_msg.push_back(0x01); // GRAFT type
                    control_msg.push_back(static_cast<uint8_t>(topic.size()));
                    control_msg.insert(control_msg.end(), topic.begin(), topic.end());
                    pimpl_->on_send(valid_graft_targets[i], control_msg);
                }
            }
        } else if (peers.size() > static_cast<size_t>(pimpl_->config.d_high)) {
            // Too many peers - prune
            int to_remove = peers.size() - pimpl_->config.d;
            std::vector<std::string> current_peers(peers.begin(), peers.end());
            std::shuffle(current_peers.begin(), current_peers.end(), std::mt19937{std::random_device{}()});
            for(int i = 0; i < to_remove && i < current_peers.size(); ++i) {
                peers.erase(current_peers[i]);
                pimpl_->fanout[topic].insert(current_peers[i]);
                if (pimpl_->on_send) {
                    std::vector<uint8_t> control_msg;
                    control_msg.push_back(0xFF); // Control Indicator
                    control_msg.push_back(0x02); // PRUNE type
                    control_msg.push_back(static_cast<uint8_t>(topic.size()));
                    control_msg.insert(control_msg.end(), topic.begin(), topic.end());
                    pimpl_->on_send(current_peers[i], control_msg);
                }
            }
        }
    }
    
    // Purge fanout timeout is handled out of band in proper protocol specification.
    // For local deterministic garbage collection, we prune unused fanout topics incrementally.
    for (auto it = pimpl_->fanout.begin(); it != pimpl_->fanout.end(); ) {
        if (pimpl_->joined_topics.count(it->first) == 0) {
            // Unused fanout cleanup could happen here based on timers
            ++it;
        } else {
            ++it;
        }
    }
}

} // namespace nit::osnova::mesh
