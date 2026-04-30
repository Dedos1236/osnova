#include "routing_table.h"
#include <algorithm>
#include <bit>

namespace nit::osnova::mesh {

namespace {
    // Calculates the bitwise XOR distance, returning the index of the most significant differing bit.
    // Index 0 is the least significant bit, index 255 is the most significant bit.
    // If they are equal, returns 0.
    size_t calculate_distance_msb(const NodeId& id1, const NodeId& id2) {
        for (size_t i = 0; i < 32; ++i) {
            uint8_t xor_val = id1[i] ^ id2[i];
            if (xor_val != 0) {
                // Find highest set bit in this byte
                size_t bit_pos = 7;
                while ((xor_val & (1 << bit_pos)) == 0) {
                    bit_pos--;
                }
                return (31 - i) * 8 + bit_pos;
            }
        }
        return 0; // Identical
    }

    struct DistanceComparator {
        NodeId target;
        DistanceComparator(const NodeId& t) : target(t) {}
        
        bool operator()(const Contact& a, const Contact& b) const {
            // Compare full 256-bit distance
            for (size_t i = 0; i < 32; ++i) {
                uint8_t da = a.id[i] ^ target[i];
                uint8_t db = b.id[i] ^ target[i];
                if (da != db) {
                    return da < db;
                }
            }
            return false; // Equal distance
        }
    };
}

// --- KBucket ---

bool KBucket::add_contact(const Contact& contact) {
    auto it = std::find_if(contacts_.begin(), contacts_.end(), 
        [&contact](const Contact& c) { return c.id == contact.id; });
        
    if (it != contacts_.end()) {
        // Move to back (most recently seen)
        contacts_.splice(contacts_.end(), contacts_, it);
        contacts_.back().last_seen = std::chrono::steady_clock::now();
        contacts_.back().fail_count = 0;
        last_changed_ = std::chrono::steady_clock::now();
        return true;
    }
    
    if (contacts_.size() < K) {
        contacts_.push_back(contact);
        contacts_.back().last_seen = std::chrono::steady_clock::now();
        last_changed_ = std::chrono::steady_clock::now();
        return true;
    }
    
    return false; // Bucket full
}

bool KBucket::remove_contact(const NodeId& id) {
    auto it = std::find_if(contacts_.begin(), contacts_.end(), 
        [&id](const Contact& c) { return c.id == id; });
        
    if (it != contacts_.end()) {
        contacts_.erase(it);
        last_changed_ = std::chrono::steady_clock::now();
        return true;
    }
    return false;
}

void KBucket::touch_contact(const NodeId& id) {
    auto it = std::find_if(contacts_.begin(), contacts_.end(), 
        [&id](const Contact& c) { return c.id == id; });
        
    if (it != contacts_.end()) {
        contacts_.splice(contacts_.end(), contacts_, it); // Move to back
        contacts_.back().last_seen = std::chrono::steady_clock::now();
    }
}

std::vector<Contact> KBucket::get_contacts() const {
    return std::vector<Contact>(contacts_.begin(), contacts_.end());
}

bool KBucket::is_full() const {
    return contacts_.size() >= K;
}

bool KBucket::contains(const NodeId& id) const {
    return std::find_if(contacts_.begin(), contacts_.end(), 
        [&id](const Contact& c) { return c.id == id; }) != contacts_.end();
}


// --- RoutingTable ---

RoutingTable::RoutingTable(const NodeId& my_id) : my_id_(my_id) {
    // 256 bits = up to 256 buckets
    buckets_.resize(256);
}

RoutingTable::~RoutingTable() = default;

size_t RoutingTable::get_bucket_index(const NodeId& target) const {
    if (target == my_id_) return 0;
    return calculate_distance_msb(my_id_, target);
}

void RoutingTable::update_contact(const Contact& contact) {
    if (contact.id == my_id_) return;

    std::lock_guard<std::mutex> lock(mutex_);
    size_t idx = get_bucket_index(contact.id);
    
    if (idx < buckets_.size()) {
        if (!buckets_[idx].add_contact(contact)) {
            // Bucket is full. We attempt to split or ping the oldest contact.
            auto bucket_contacts = buckets_[idx].get_contacts();
            if (!bucket_contacts.empty()) {
                // If the oldest contact is unresponsive based on active deterministic fail limits, rotate out
                if (bucket_contacts.front().fail_count >= 3) {
                    buckets_[idx].remove_contact(bucket_contacts.front().id);
                    buckets_[idx].add_contact(contact);
                }
            }
        }
    }
}

void RoutingTable::remove_contact(const NodeId& id) {
    if (id == my_id_) return;

    std::lock_guard<std::mutex> lock(mutex_);
    size_t idx = get_bucket_index(id);
    
    if (idx < buckets_.size()) {
        buckets_[idx].remove_contact(id);
    }
}

std::vector<Contact> RoutingTable::find_closest_nodes(const NodeId& target, size_t count) const {
    std::lock_guard<std::mutex> lock(mutex_);
    std::vector<Contact> closest;
    
    size_t target_idx = get_bucket_index(target);
    
    // Grab contacts from the target bucket
    auto bucket_contacts = buckets_[target_idx].get_contacts();
    closest.insert(closest.end(), bucket_contacts.begin(), bucket_contacts.end());
    
    // If we need more, spread outwards
    int offset = 1;
    while (closest.size() < count && (target_idx >= offset || target_idx + offset < buckets_.size())) {
        if (target_idx >= offset) {
            auto lower_contacts = buckets_[target_idx - offset].get_contacts();
            closest.insert(closest.end(), lower_contacts.begin(), lower_contacts.end());
        }
        if (target_idx + offset < buckets_.size()) {
            auto upper_contacts = buckets_[target_idx + offset].get_contacts();
            closest.insert(closest.end(), upper_contacts.begin(), upper_contacts.end());
        }
        offset++;
    }
    
    // Sort all gathered contacts by actual XOR distance to target
    std::sort(closest.begin(), closest.end(), DistanceComparator(target));
    
    if (closest.size() > count) {
        closest.resize(count);
    }
    
    return closest;
}

size_t RoutingTable::get_total_contacts() const {
    std::lock_guard<std::mutex> lock(mutex_);
    size_t total = 0;
    for (const auto& bucket : buckets_) {
        total += bucket.get_contacts().size();
    }
    return total;
}

} // namespace nit::osnova::mesh
