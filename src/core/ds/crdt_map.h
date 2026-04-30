#pragma once

#include <vector>
#include <string>
#include <cstdint>
#include <mutex>
#include <map>

namespace nit::osnova::ds {

/**
 * @brief CRDT Map (Conflict-Free Replicated Data Type).
 * Native OSNOVA engine component for handling decentralized multi-master
 * data structures. Used heavily in Group Chat states where multiple peers 
 * update permissions, names, and lists concurrently without coordination, 
 * perfectly merging into an identical synchronized state mathematically.
 */
class CrdtMap {
public:
    CrdtMap(std::string node_id);
    ~CrdtMap();

    void put(const std::string& key, const std::string& value);
    std::string get(const std::string& key) const;
    void remove(const std::string& key);

    struct StateDelta {
        std::vector<uint8_t> payload;
    };

    /**
     * @brief Serialize local changes into a transport-ready delta.
     */
    StateDelta generate_delta() const;

    /**
     * @brief Perfectly merge remote changes with the local state avoiding all conflicts.
     */
    void merge(const StateDelta& remote_delta);

private:
    std::string node_id_;
    mutable std::mutex mtx_;
    
    // Last-Write-Wins element set structure
    struct Element {
        std::string value;
        uint64_t timestamp;
        std::string author_node;
        bool is_deleted;
    };

    std::map<std::string, Element> state_;
    uint64_t logical_clock_ = 0;
};

} // namespace nit::osnova::ds
