#pragma once

#include <cstdint>
#include <vector>
#include <array>
#include <string>
#include <list>
#include <mutex>
#include <functional>
#include <unordered_map>

namespace nit::osnova::mesh {

constexpr size_t KADEMLIA_ID_SIZE = 32; // 256-bit ID space
using NodeId = std::array<uint8_t, KADEMLIA_ID_SIZE>;

struct PeerContact {
    NodeId id;
    std::string ip;
    uint16_t port;
    uint64_t last_seen;

    bool operator==(const PeerContact& other) const {
        return id == other.id;
    }
};

/**
 * @brief Kademlia Distributed Hash Table (DHT).
 * Used by OSNOVA to discover peers and locate distributed resources 
 * (like mesh relay nodes, content hashes) without a centralized tracker.
 */
class KademliaDht {
public:
    static constexpr int K_BUCKET_SIZE = 20;
    static constexpr int ALPHA = 3; // concurrency parameter

    explicit KademliaDht(const NodeId& local_id);
    ~KademliaDht();

    /**
     * @brief Update the routing table with a newly observed contact.
     */
    void update_contact(const PeerContact& contact);

    /**
     * @brief Find the K closest nodes to a given target ID.
     */
    std::vector<PeerContact> find_closest_nodes(const NodeId& target, size_t count = K_BUCKET_SIZE) const;

    /**
     * @brief Store a value in the local DHT storage.
     */
    void store_value(const std::string& key, const std::vector<uint8_t>& value);

    /**
     * @brief Retrieve a value from the local DHT storage.
     */
    bool find_value(const std::string& key, std::vector<uint8_t>& out_value) const;

    /**
     * @brief Calculate the XOR distance between two Node IDs.
     */
    static std::array<uint8_t, KADEMLIA_ID_SIZE> xor_distance(const NodeId& a, const NodeId& b);

private:
    struct KBucket {
        std::list<PeerContact> contacts;
        std::list<PeerContact> replacement_cache;
    };

    NodeId local_id_;
    std::array<KBucket, KADEMLIA_ID_SIZE * 8> buckets_; // 256 buckets
    std::unordered_map<std::string, std::vector<uint8_t>> storage_;
    mutable std::mutex mutex_;

    int get_bucket_index(const NodeId& other_id) const;

public:
    std::function<bool(const PeerContact&)> ping_handler;
};

} // namespace nit::osnova::mesh
