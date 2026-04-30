#include "kademlia_dht.h"
#include <algorithm>

namespace nit::osnova::mesh {

KademliaDht::KademliaDht(const NodeId& local_id) : local_id_(local_id) {
}

KademliaDht::~KademliaDht() = default;

std::array<uint8_t, KADEMLIA_ID_SIZE> KademliaDht::xor_distance(const NodeId& a, const NodeId& b) {
    std::array<uint8_t, KADEMLIA_ID_SIZE> dist;
    for (size_t i = 0; i < KADEMLIA_ID_SIZE; ++i) {
        dist[i] = a[i] ^ b[i];
    }
    return dist;
}

int KademliaDht::get_bucket_index(const NodeId& other_id) const {
    auto dist = xor_distance(local_id_, other_id);
    // Find the highest bit set
    for (size_t i = 0; i < KADEMLIA_ID_SIZE; ++i) {
        if (dist[i] != 0) {
            uint8_t val = dist[i];
            int bit = 7;
            while ((val & (1 << bit)) == 0) bit--;
            return (KADEMLIA_ID_SIZE - 1 - i) * 8 + bit;
        }
    }
    return 0; // Same ID
}

void KademliaDht::update_contact(const PeerContact& contact) {
    if (contact.id == local_id_) return;

    std::lock_guard<std::mutex> lock(mutex_);
    int bucket_idx = get_bucket_index(contact.id);
    auto& bucket = buckets_[bucket_idx];

    // Find if already exists
    auto it = std::find(bucket.contacts.begin(), bucket.contacts.end(), contact);
    if (it != bucket.contacts.end()) {
        // Move to tail (most recently seen)
        PeerContact updated = *it;
        updated.last_seen = contact.last_seen;
        bucket.contacts.erase(it);
        bucket.contacts.push_back(updated);
    } else {
        if (bucket.contacts.size() < K_BUCKET_SIZE) {
            bucket.contacts.push_back(contact);
        } else {
            // Ping the least recently seen (head).
            PeerContact least_recently_seen = bucket.contacts.front();
            bool ping_success = false;
            if (ping_handler) {
                // Must unlock to prevent deadlock during synchronous ping
                mutex_.unlock();
                ping_success = ping_handler(least_recently_seen);
                mutex_.lock();
            }

            if (ping_success) {
                // Evict head, push it to tail, put new contact in replacement cache
                if (!bucket.contacts.empty() && bucket.contacts.front() == least_recently_seen) {
                    bucket.contacts.pop_front();
                    bucket.contacts.push_back(least_recently_seen);
                }
                
                auto r_it = std::find(bucket.replacement_cache.begin(), bucket.replacement_cache.end(), contact);
                if (r_it != bucket.replacement_cache.end()) {
                    bucket.replacement_cache.erase(r_it);
                }
                bucket.replacement_cache.push_back(contact);
                if (bucket.replacement_cache.size() > K_BUCKET_SIZE) {
                    bucket.replacement_cache.pop_front();
                }
            } else {
                // Least recently seen failed to respond, remove it and insert new contact
                if (!bucket.contacts.empty() && bucket.contacts.front() == least_recently_seen) {
                    bucket.contacts.pop_front();
                }
                bucket.contacts.push_back(contact);
            }
        }
    }
}

std::vector<PeerContact> KademliaDht::find_closest_nodes(const NodeId& target, size_t count) const {
    std::lock_guard<std::mutex> lock(mutex_);
    std::vector<PeerContact> all_nodes;

    for (const auto& bucket : buckets_) {
        for (const auto& contact : bucket.contacts) {
            all_nodes.push_back(contact);
        }
    }

    // Sort by XOR distance to target
    std::sort(all_nodes.begin(), all_nodes.end(), [&target](const PeerContact& a, const PeerContact& b) {
        auto dist_a = xor_distance(a.id, target);
        auto dist_b = xor_distance(b.id, target);
        for (size_t i = 0; i < KADEMLIA_ID_SIZE; ++i) {
            if (dist_a[i] < dist_b[i]) return true;
            if (dist_a[i] > dist_b[i]) return false;
        }
        return false;
    });

    if (all_nodes.size() > count) {
        all_nodes.resize(count);
    }

    return all_nodes;
}

void KademliaDht::store_value(const std::string& key, const std::vector<uint8_t>& value) {
    std::lock_guard<std::mutex> lock(mutex_);
    storage_[key] = value;
}

bool KademliaDht::find_value(const std::string& key, std::vector<uint8_t>& out_value) const {
    std::lock_guard<std::mutex> lock(mutex_);
    auto it = storage_.find(key);
    if (it != storage_.end()) {
        out_value = it->second;
        return true;
    }
    return false;
}

} // namespace nit::osnova::mesh
