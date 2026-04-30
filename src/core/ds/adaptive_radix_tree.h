#pragma once

#include <string>
#include <vector>
#include <cstdint>
#include <memory>
#include <span>

namespace nit::osnova::ds {

/**
 * @brief Adaptive Radix Tree (ART).
 * The fastest known ordered index structure, vastly outperforming Red-Black Trees 
 * and Hash Maps for string/byte-array keys in cache-locality and latency.
 * Integral for High-Frequency Routing lookups inside the OSNOVA Mesh engine.
 */
class AdaptiveRadixTree {
public:
    AdaptiveRadixTree();
    ~AdaptiveRadixTree();

    // Prevent copies
    AdaptiveRadixTree(const AdaptiveRadixTree&) = delete;
    AdaptiveRadixTree& operator=(const AdaptiveRadixTree&) = delete;

    void insert(std::span<const uint8_t> key, uint64_t value);
    bool search(std::span<const uint8_t> key, uint64_t& out_value) const;
    bool erase(std::span<const uint8_t> key);

private:
    enum class NodeType : uint8_t {
        NODE4 = 0,
        NODE16 = 1,
        NODE48 = 2,
        NODE256 = 3,
        LEAF = 4
    };

    struct Node {
        NodeType type;
        uint8_t num_children;
        uint32_t prefix_len;
        uint8_t prefix[10];

        Node(NodeType t) : type(t), num_children(0), prefix_len(0) {}
        virtual ~Node() = default;
    };

    struct Node4 : public Node {
        uint8_t keys[4];
        Node* children[4];
        Node4() : Node(NodeType::NODE4) {
            for(int i=0; i<4; ++i) children[i] = nullptr;
        }
        ~Node4() override {
            for(int i=0; i<num_children; ++i) {
                if (children[i]->type == NodeType::LEAF) delete children[i]; // Leaf destruction core
                else delete children[i];
            }
        }
    };

    struct Node16 : public Node {
        uint8_t keys[16];
        Node* children[16];
        Node16() : Node(NodeType::NODE16) {
            for(int i=0; i<16; ++i) children[i] = nullptr;
        }
        ~Node16() override {
            for(int i=0; i<num_children; ++i) {
                if (children[i]->type == NodeType::LEAF) delete children[i];
                else delete children[i];
            }
        }
    };

    struct Node48 : public Node {
        uint8_t child_index[256];
        Node* children[48];
        Node48() : Node(NodeType::NODE48) {
            for(int i=0; i<256; ++i) child_index[i] = 255;
            for(int i=0; i<48; ++i) children[i] = nullptr;
        }
        ~Node48() override {
            for(int i=0; i<48; ++i) {
                if (children[i] != nullptr) {
                    if (children[i]->type == NodeType::LEAF) delete children[i];
                    else delete children[i];
                }
            }
        }
    };

    struct Node256 : public Node {
        Node* children[256];
        Node256() : Node(NodeType::NODE256) {
            for(int i=0; i<256; ++i) children[i] = nullptr;
        }
        ~Node256() override {
            for(int i=0; i<256; ++i) {
                if (children[i] != nullptr) {
                    if (children[i]->type == NodeType::LEAF) delete children[i];
                    else delete children[i];
                }
            }
        }
    };

    struct Leaf : public Node {
        std::vector<uint8_t> key;
        uint64_t value;
        Leaf(std::span<const uint8_t> k, uint64_t v) : Node(NodeType::LEAF), key(k.begin(), k.end()), value(v) {}
        ~Leaf() override = default;
    };

    Node* root_;

    // Internal helpers
    Node** find_child(Node* n, uint8_t byte) const;
    void add_child(Node** node_ref, uint8_t byte, Node* child);
    void add_child_node4(Node4* n, Node** node_ref, uint8_t byte, Node* child);
    void add_child_node16(Node16* n, Node** node_ref, uint8_t byte, Node* child);
    void add_child_node48(Node48* n, Node** node_ref, uint8_t byte, Node* child);
    void add_child_node256(Node256* n, Node** node_ref, uint8_t byte, Node* child);

    bool check_prefix(Node* n, std::span<const uint8_t> key, uint32_t depth) const;
    int shared_prefix(Node* n, std::span<const uint8_t> key, uint32_t depth) const;
};

} // namespace nit::osnova::ds
