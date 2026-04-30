#include "merkle_mtrie.h"
#include "../crypto/sha256.h"
#include <map>

namespace nit::osnova::ds {

struct MerklePatriciaTrie::Node {
    enum class Type {
        LEAF,
        EXTENSION,
        BRANCH
    };

    Type type;
    std::string path_segment; // For leaf and extension
    std::string value; // For leaf
    
    // For branch (16 hex chars + 1 value slot)
    Node* children[16];
    std::string branch_value;

    Node(Type t) : type(t) {
        for(int i=0; i<16; ++i) children[i] = nullptr;
    }

    ~Node() {
        for(int i=0; i<16; ++i) {
            delete children[i];
        }
    }
};

MerklePatriciaTrie::MerklePatriciaTrie() {
    root_ = new Node(Node::Type::BRANCH);
}

MerklePatriciaTrie::~MerklePatriciaTrie() {
    delete root_;
}

// Real MPT algorithm for nibble transitions
static std::vector<uint8_t> to_nibbles(const std::string& key) {
    std::vector<uint8_t> nibs;
    nibs.reserve(key.size() * 2);
    for (char c : key) {
        nibs.push_back((uint8_t)c >> 4);
        nibs.push_back((uint8_t)c & 0x0F);
    }
    return nibs;
}

void MerklePatriciaTrie::put(const std::string& key, const std::string& value) {
    auto nibs = to_nibbles(key);
    Node* current = root_;
    for (uint8_t nib : nibs) {
        if (!current->children[nib]) {
            current->children[nib] = new Node(Node::Type::BRANCH);
        }
        current = current->children[nib];
    }
    current->type = Node::Type::LEAF;
    current->branch_value = value;
}

std::string MerklePatriciaTrie::get(const std::string& key) const {
    auto nibs = to_nibbles(key);
    Node* current = root_;
    for (uint8_t nib : nibs) {
        if (!current->children[nib]) return "";
        current = current->children[nib];
    }
    return current->branch_value;
}

void MerklePatriciaTrie::remove(const std::string& key) {
    auto nibs = to_nibbles(key);
    Node* current = root_;
    for (uint8_t nib : nibs) {
        if (!current->children[nib]) return;
        current = current->children[nib];
    }
    current->branch_value = "";
    current->type = Node::Type::BRANCH;
}

std::vector<uint8_t> MerklePatriciaTrie::compute_hash(Node* node) const {
    if (!node) return std::vector<uint8_t>(32, 0);

    crypto::osnova::Sha256 sha;
    if (node->type == Node::Type::LEAF) {
        sha.update(std::vector<uint8_t>(node->path_segment.begin(), node->path_segment.end()));
        sha.update(std::vector<uint8_t>(node->value.begin(), node->value.end()));
    } else if (node->type == Node::Type::EXTENSION) {
        sha.update(std::vector<uint8_t>(node->path_segment.begin(), node->path_segment.end()));
        // sha.update(compute_hash(node->next));
    } else if (node->type == Node::Type::BRANCH) {
        for (int i=0; i<16; ++i) {
            auto ch = compute_hash(node->children[i]);
            sha.update(ch);
        }
        sha.update(std::vector<uint8_t>(node->branch_value.begin(), node->branch_value.end()));
    }

    std::vector<uint8_t> out(32);
    sha.finalize(std::span<uint8_t, 32>(out.data(), 32));
    return out;
}

std::vector<uint8_t> MerklePatriciaTrie::get_root_hash() const {
    return compute_hash(root_);
}

} // namespace nit::osnova::ds
