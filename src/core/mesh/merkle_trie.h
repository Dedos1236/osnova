#pragma once

#include <cstdint>
#include <vector>
#include <span>
#include <memory>
#include <string>

namespace nit::osnova::mesh {

/**
 * @brief Authenticated Dictionary (Merkle Trie) implementation.
 * Used for maintaining consensus state in the distributed ledger.
 * This resembles Ethereum's Modified Merkle Patricia Trie.
 */
class MerkleTrie {
public:
    static constexpr size_t HASH_SIZE = 32;

    MerkleTrie();
    ~MerkleTrie();

    /**
     * @brief Insert or update a key-value pair.
     */
    void put(const std::vector<uint8_t>& key, const std::vector<uint8_t>& value);

    /**
     * @brief Retrieve a value by its key.
     * @return Empty vector if not found.
     */
    std::vector<uint8_t> get(const std::vector<uint8_t>& key) const;

    /**
     * @brief Removes a key-value pair from the trie.
     */
    bool remove(const std::vector<uint8_t>& key);

    /**
     * @brief Calculate the 32-byte root hash of the Trie.
     */
    std::vector<uint8_t> root_hash() const;

    /**
     * @brief Generate a Merkle proof for a particular key.
     */
    std::vector<std::vector<uint8_t>> generate_proof(const std::vector<uint8_t>& key) const;

    /**
     * @brief Verify a Merkle proof.
     */
    static bool verify_proof(
        const std::vector<uint8_t>& root_hash,
        const std::vector<uint8_t>& key,
        const std::vector<uint8_t>& value, // if empty, verifying non-inclusion
        const std::vector<std::vector<uint8_t>>& proof);

private:
    struct Impl;
    std::unique_ptr<Impl> pimpl_;
};

} // namespace nit::osnova::mesh
