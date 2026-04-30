#pragma once

#include <string>
#include <vector>
#include <cstdint>

namespace nit::osnova::ds {

/**
 * @brief Merkle Patricia Trie (MPT) implementation.
 * Used for authenticated state representation in decentralized systems like Ethereum.
 * Ideal for verifiable key-value data in OSNOVA mesh routing state.
 */
class MerklePatriciaTrie {
public:
    MerklePatriciaTrie();
    ~MerklePatriciaTrie();

    void put(const std::string& key, const std::string& value);
    std::string get(const std::string& key) const;
    void remove(const std::string& key);

    /**
     * @brief Get the cryptographic state root hash representing 
     * the entire trie at this moment.
     */
    std::vector<uint8_t> get_root_hash() const;

private:
    struct Node;
    Node* root_;

    std::vector<uint8_t> compute_hash(Node* node) const;
};

} // namespace nit::osnova::ds
