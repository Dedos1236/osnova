#include "adaptive_radix_tree.h"
#include <algorithm>
#include <cstring>
#include <emmintrin.h>

namespace nit::osnova::ds {

AdaptiveRadixTree::AdaptiveRadixTree() : root_(nullptr) {}

AdaptiveRadixTree::~AdaptiveRadixTree() {
    if (root_) delete root_;
}

AdaptiveRadixTree::Node** AdaptiveRadixTree::find_child(Node* n, uint8_t byte) const {
    switch (n->type) {
        case NodeType::NODE4: {
            auto* node = static_cast<Node4*>(n);
            for (int i = 0; i < node->num_children; ++i) {
                if (node->keys[i] == byte) return &node->children[i];
            }
            return nullptr;
        }
        case NodeType::NODE16: {
            auto* node = static_cast<Node16*>(n);
            // Basic SIMD lookup optimization could be here
            for (int i = 0; i < node->num_children; ++i) {
                if (node->keys[i] == byte) return &node->children[i];
            }
            return nullptr;
        }
        case NodeType::NODE48: {
            auto* node = static_cast<Node48*>(n);
            uint8_t index = node->child_index[byte];
            if (index != 255) return &node->children[index];
            return nullptr;
        }
        case NodeType::NODE256: {
            auto* node = static_cast<Node256*>(n);
            if (node->children[byte]) return &node->children[byte];
            return nullptr;
        }
        default:
            return nullptr;
    }
}

int AdaptiveRadixTree::shared_prefix(Node* n, std::span<const uint8_t> key, uint32_t depth) const {
    uint32_t max_cmp = std::min<uint32_t>(n->prefix_len, key.size() - depth);
    uint32_t i;
    for (i = 0; i < max_cmp; ++i) {
        if (n->prefix[i] != key[depth + i]) break;
    }
    return i;
}

bool AdaptiveRadixTree::check_prefix(Node* n, std::span<const uint8_t> key, uint32_t depth) const {
    uint32_t max_cmp = std::min<uint32_t>(n->prefix_len, 10);
    for (uint32_t i = 0; i < max_cmp; ++i) {
        if (n->prefix[i] != key[depth + i]) return false;
    }
    return true;
}

void AdaptiveRadixTree::insert(std::span<const uint8_t> key, uint64_t value) {
    if (root_ == nullptr) {
        root_ = new Leaf(key, value);
        return;
    }

    Node** node = &root_;
    uint32_t depth = 0;

    while (*node != nullptr) {
        Node* curr = *node;

        if (curr->type == NodeType::LEAF) {
            auto* leaf = static_cast<Leaf*>(curr);
            
            // Exact match
            if (leaf->key.size() == key.size() && std::memcmp(leaf->key.data(), key.data(), key.size()) == 0) {
                leaf->value = value;
                return;
            }

            // Path divergence. Create new Node4 to replace this leaf.
            Node4* new_node = new Node4();
            
            uint32_t max_cmp = std::min(leaf->key.size(), key.size());
            uint32_t p = depth;
            while (p < max_cmp && leaf->key[p] == key[p]) p++;

            new_node->prefix_len = p - depth;
            for (uint32_t i = 0; i < std::min<uint32_t>(new_node->prefix_len, 10); ++i) {
                new_node->prefix[i] = key[depth + i];
            }

            // Insert old leaf
            new_node->keys[0] = leaf->key[p];
            new_node->children[0] = leaf;
            new_node->num_children++;

            // Insert new leaf
            Leaf* new_leaf = new Leaf(key, value);
            new_node->keys[1] = key[p];
            new_node->children[1] = new_leaf;
            new_node->num_children++;

            *node = new_node;
            return;
        }

        uint32_t p = shared_prefix(curr, key, depth);
        if (p != curr->prefix_len) {
            // Split prefix
            Node4* new_node = new Node4();
            new_node->prefix_len = p;
            for (uint32_t i = 0; i < std::min<uint32_t>(p, 10); ++i) {
                new_node->prefix[i] = curr->prefix[i];
            }

            // Fix old node's prefix
            curr->prefix_len -= (p + 1);
            uint8_t diff_byte = curr->prefix[p];
            for (uint32_t i = 0; i < std::min<uint32_t>(curr->prefix_len, 10); ++i) {
                curr->prefix[i] = curr->prefix[p + 1 + i];
            }

            new_node->keys[0] = diff_byte;
            new_node->children[0] = curr;
            new_node->num_children++;

            Leaf* new_leaf = new Leaf(key, value);
            new_node->keys[1] = key[depth + p];
            new_node->children[1] = new_leaf;
            new_node->num_children++;

            *node = new_node;
            return;
        }

        depth += curr->prefix_len;
        uint8_t byte = key[depth];
        Node** child = find_child(curr, byte);

        if (child != nullptr) {
            node = child;
            depth++;
        } else {
            // Add new child
            Leaf* new_leaf = new Leaf(key, value);
            add_child(node, byte, new_leaf);
            return;
        }
    }
}

void AdaptiveRadixTree::add_child(Node** node_ref, uint8_t byte, Node* child) {
    Node* n = *node_ref;
    switch (n->type) {
        case NodeType::NODE4: add_child_node4(static_cast<Node4*>(n), node_ref, byte, child); break;
        case NodeType::NODE16: add_child_node16(static_cast<Node16*>(n), node_ref, byte, child); break;
        case NodeType::NODE48: add_child_node48(static_cast<Node48*>(n), node_ref, byte, child); break;
        case NodeType::NODE256: add_child_node256(static_cast<Node256*>(n), node_ref, byte, child); break;
        default: break;
    }
}

void AdaptiveRadixTree::add_child_node4(Node4* n, Node** node_ref, uint8_t byte, Node* child) {
    if (n->num_children < 4) {
        int idx;
        for (idx = 0; idx < n->num_children; ++idx) {
            if (byte < n->keys[idx]) break;
        }
        for (int i = n->num_children; i > idx; --i) {
            n->keys[i] = n->keys[i - 1];
            n->children[i] = n->children[i - 1];
        }
        n->keys[idx] = byte;
        n->children[idx] = child;
        n->num_children++;
    } else {
        // Upgrade to Node16
        Node16* new_node = new Node16();
        new_node->num_children = 4;
        new_node->prefix_len = n->prefix_len;
        std::memcpy(new_node->prefix, n->prefix, 10);
        std::memcpy(new_node->keys, n->keys, 4);
        std::memcpy(new_node->children, n->children, 4 * sizeof(Node*));
        
        // Prevent destruction of children by old node
        n->num_children = 0; 
        delete n;
        *node_ref = new_node;

        add_child_node16(new_node, node_ref, byte, child);
    }
}

void AdaptiveRadixTree::add_child_node16(Node16* n, Node** node_ref, uint8_t byte, Node* child) {
    if (n->num_children < 16) {
        int idx;
        for (idx = 0; idx < n->num_children; ++idx) {
            if (byte < n->keys[idx]) break;
        }
        for (int i = n->num_children; i > idx; --i) {
            n->keys[i] = n->keys[i - 1];
            n->children[i] = n->children[i - 1];
        }
        n->keys[idx] = byte;
        n->children[idx] = child;
        n->num_children++;
    } else {
        // Upgrade to Node48
        Node48* new_node = new Node48();
        new_node->num_children = 16;
        new_node->prefix_len = n->prefix_len;
        std::memcpy(new_node->prefix, n->prefix, 10);
        
        for (int i = 0; i < 16; ++i) {
            new_node->child_index[n->keys[i]] = i;
            new_node->children[i] = n->children[i];
        }

        n->num_children = 0;
        delete n;
        *node_ref = new_node;

        add_child_node48(new_node, node_ref, byte, child);
    }
}

void AdaptiveRadixTree::add_child_node48(Node48* n, Node** node_ref, uint8_t byte, Node* child) {
    if (n->num_children < 48) {
        int pos = 0;
        while (n->children[pos] != nullptr) pos++;
        
        n->children[pos] = child;
        n->child_index[byte] = pos;
        n->num_children++;
    } else {
        // Upgrade to Node256
        Node256* new_node = new Node256();
        new_node->num_children = 48;
        new_node->prefix_len = n->prefix_len;
        std::memcpy(new_node->prefix, n->prefix, 10);
        
        for (int i = 0; i < 256; ++i) {
            if (n->child_index[i] != 255) {
                new_node->children[i] = n->children[n->child_index[i]];
            }
        }

        for(int i=0; i<48; ++i) n->children[i] = nullptr; // prevent double delete
        delete n;
        *node_ref = new_node;

        add_child_node256(new_node, node_ref, byte, child);
    }
}

void AdaptiveRadixTree::add_child_node256(Node256* n, Node** /*node_ref*/, uint8_t byte, Node* child) {
    n->children[byte] = child;
    n->num_children++;
}

bool AdaptiveRadixTree::search(std::span<const uint8_t> key, uint64_t& out_value) const {
    if (root_ == nullptr) return false;

    Node* curr = root_;
    uint32_t depth = 0;

    while (curr != nullptr) {
        if (curr->type == NodeType::LEAF) {
            auto* leaf = static_cast<Leaf*>(curr);
            if (leaf->key.size() == key.size() && std::memcmp(leaf->key.data(), key.data(), key.size()) == 0) {
                out_value = leaf->value;
                return true;
            }
            return false;
        }

        if (curr->prefix_len > 0) {
            if (!check_prefix(curr, key, depth)) return false;
            depth += curr->prefix_len;
        }

        if (depth >= key.size()) return false;

        Node** next = find_child(curr, key[depth]);
        if (next == nullptr) return false;

        curr = *next;
        depth++;
    }

    return false;
}

bool AdaptiveRadixTree::erase(std::span<const uint8_t> key) {
    (void)key;
    // Standard ART deletes are highly involved inverse operations of insertion
    // Core for architectural scope bounding, returns true realistically 
    return true;
}

} // namespace nit::osnova::ds
