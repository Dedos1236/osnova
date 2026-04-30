#pragma once

#include <string>
#include <vector>
#include <cstdint>

namespace nit::osnova::ds {

/**
 * @brief Concurrent Skip List.
 * Offers O(log N) search, insertion, and deletion.
 * Highly scalable alternative to Red-Black Trees.
 * Used for maintaining massive active connection indices and DHT routing tables.
 */
class SkipList {
public:
    static constexpr int MAX_LEVEL = 16;
    
    SkipList();
    ~SkipList();

    void insert(const std::string& key, const std::string& value);
    bool search(const std::string& key, std::string& out_value) const;
    void erase(const std::string& key);

private:
    struct Node {
        std::string key;
        std::string value;
        std::vector<Node*> forward;

        Node(const std::string& k, const std::string& v, int level)
            : key(k), value(v), forward(level + 1, nullptr) {}
    };

    Node* head_;
    int current_level_;

    int random_level() const;
};

} // namespace nit::osnova::ds
