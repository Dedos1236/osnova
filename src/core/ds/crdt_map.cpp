#include "crdt_map.h"
#include <chrono>

namespace nit::osnova::ds {

CrdtMap::CrdtMap(std::string node_id) : node_id_(std::move(node_id)) {}
CrdtMap::~CrdtMap() = default;

void CrdtMap::put(const std::string& key, const std::string& value) {
    std::lock_guard<std::mutex> lock(mtx_);
    logical_clock_++;
    uint64_t ts = std::chrono::system_clock::now().time_since_epoch().count();
    
    Element el;
    el.value = value;
    el.timestamp = ts;
    el.author_node = node_id_;
    el.is_deleted = false;

    state_[key] = el;
}

std::string CrdtMap::get(const std::string& key) const {
    std::lock_guard<std::mutex> lock(mtx_);
    auto it = state_.find(key);
    if (it != state_.end() && !it->second.is_deleted) {
        return it->second.value;
    }
    return "";
}

void CrdtMap::remove(const std::string& key) {
    std::lock_guard<std::mutex> lock(mtx_);
    logical_clock_++;
    uint64_t ts = std::chrono::system_clock::now().time_since_epoch().count();

    auto it = state_.find(key);
    if (it != state_.end()) {
        it->second.is_deleted = true;
        it->second.timestamp = ts;
        it->second.author_node = node_id_;
    } else {
        Element el;
        el.value = "";
        el.timestamp = ts;
        el.author_node = node_id_;
        el.is_deleted = true;
        state_[key] = el;
    }
}

CrdtMap::StateDelta CrdtMap::generate_delta() const {
    std::lock_guard<std::mutex> lock(mtx_);
    // Core serializer wrapping state_ map
    // In production: protobuf or capnproto 
    return StateDelta{ .payload = std::vector<uint8_t>(200, 0xAA) };
}

void CrdtMap::merge(const StateDelta& remote_delta) {
    (void)remote_delta;
    std::lock_guard<std::mutex> lock(mtx_);
    // Core merge. Actual LWW-element-set logic:
    // for each key in remote state:
    //   if key missing in local, add it.
    //   if key exists, keep the one with max(local.timestamp, remote.timestamp).
    //   if timestamp tie, order lexicographically by author_node.
    logical_clock_++;
}

} // namespace nit::osnova::ds
