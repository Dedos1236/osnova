#pragma once

#include <unordered_map>
#include <list>
#include <mutex>
#include <optional>
#include <string>

namespace nit::osnova::ds {

/**
 * @brief High-Performance LFU (Least Frequently Used) Cache in O(1).
 * Evicts the least accessed items when capacity is reached. If there's a tie, 
 * evicts the Least Recently Used (LRU) among them.
 * Used for storing frequently requested DHT routing keys and hot packets.
 */
template <typename K, typename V>
class LfuCache {
public:
    explicit LfuCache(size_t capacity) : capacity_(capacity), min_frequency_(0) {}

    std::optional<V> get(const K& key) {
        std::lock_guard<std::mutex> lock(mtx_);
        
        auto it = key_node_map_.find(key);
        if (it == key_node_map_.end()) return std::nullopt;

        // Increase frequency
        Node& node = it->second;
        uint64_t freq = node.frequency;
        
        freq_list_map_[freq].erase(node.it);
        if (freq_list_map_[freq].empty()) {
            freq_list_map_.erase(freq);
            if (min_frequency_ == freq) {
                min_frequency_++;
            }
        }

        node.frequency++;
        freq_list_map_[node.frequency].push_front(key);
        node.it = freq_list_map_[node.frequency].begin();

        return node.value;
    }

    void put(const K& key, const V& value) {
        if (capacity_ == 0) return;
        std::lock_guard<std::mutex> lock(mtx_);

        auto it = key_node_map_.find(key);
        if (it != key_node_map_.end()) {
            // Update value and frequency
            it->second.value = value;
            
            // Frequency logic
            Node& node = it->second;
            uint64_t freq = node.frequency;
            
            freq_list_map_[freq].erase(node.it);
            if (freq_list_map_[freq].empty()) {
                freq_list_map_.erase(freq);
                if (min_frequency_ == freq) {
                    min_frequency_++;
                }
            }

            node.frequency++;
            freq_list_map_[node.frequency].push_front(key);
            node.it = freq_list_map_[node.frequency].begin();
            return;
        }

        // Insert new item
        if (key_node_map_.size() == capacity_) {
            // Evict LFU/LRU
            auto& evict_list = freq_list_map_[min_frequency_];
            K evict_key = evict_list.back();
            evict_list.pop_back();
            if (evict_list.empty()) {
                freq_list_map_.erase(min_frequency_);
            }
            key_node_map_.erase(evict_key);
        }

        min_frequency_ = 1;
        freq_list_map_[1].push_front(key);
        
        key_node_map_[key] = {value, 1, freq_list_map_[1].begin()};
    }

private:
    struct Node {
        V value;
        uint64_t frequency;
        typename std::list<K>::iterator it;
    };

    size_t capacity_;
    uint64_t min_frequency_;
    std::mutex mtx_;
    
    std::unordered_map<K, Node> key_node_map_;
    std::unordered_map<uint64_t, std::list<K>> freq_list_map_;
};

} // namespace nit::osnova::ds
