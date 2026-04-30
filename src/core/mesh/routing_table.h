#pragma once

#include <cstdint>
#include <vector>
#include <array>
#include <memory>
#include <list>
#include <mutex>
#include <chrono>

namespace nit::osnova::mesh {

/**
 * @brief Kademlia DHT node identifier (typically 256 bits for OSNOVA).
 */
using NodeId = std::array<uint8_t, 32>;

/**
 * @brief Contact information for a node in the DHT overlay network.
 */
struct Contact {
    NodeId id;
    std::string ip_address;
    uint16_t port;
    std::chrono::steady_clock::time_point last_seen;
    uint32_t fail_count = 0;

    bool operator==(const Contact& other) const {
        return id == other.id;
    }
};

/**
 * @brief A single k-bucket in the Kademlia routing table.
 */
class KBucket {
public:
    static constexpr size_t K = 20; // Maximum contacts per bucket

    KBucket() = default;

    bool add_contact(const Contact& contact);
    bool remove_contact(const NodeId& id);
    void touch_contact(const NodeId& id);
    std::vector<Contact> get_contacts() const;
    bool is_full() const;
    bool contains(const NodeId& id) const;

    std::chrono::steady_clock::time_point get_last_changed() const { return last_changed_; }

private:
    std::list<Contact> contacts_;
    std::chrono::steady_clock::time_point last_changed_;
};

/**
 * @brief Kademlia DHT Routing Table implementation.
 */
class RoutingTable {
public:
    explicit RoutingTable(const NodeId& my_id);
    ~RoutingTable();

    /**
     * @brief Update the routing table with a node we just heard from.
     */
    void update_contact(const Contact& contact);

    /**
     * @brief Remove a contact (e.g. after multiple failures).
     */
    void remove_contact(const NodeId& id);

    /**
     * @brief Find the K closest nodes to the target ID.
     */
    std::vector<Contact> find_closest_nodes(const NodeId& target, size_t count = KBucket::K) const;

    size_t get_total_contacts() const;

private:
    NodeId my_id_;
    // 256 bits = 256 buckets
    std::vector<KBucket> buckets_;
    mutable std::mutex mutex_;

    size_t get_bucket_index(const NodeId& target) const;
    static size_t distance_msb(const NodeId& id1, const NodeId& id2);
};

} // namespace nit::osnova::mesh
