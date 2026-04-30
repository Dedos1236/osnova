#pragma once

#include <cstdint>
#include <span>
#include <vector>
#include <memory>
#include <optional>

namespace nit::crypto::osnova {

/**
 * @brief Continuous Group Key Agreement using TreeKEM (Tree Key Encapsulation Mechanism).
 * Used for secure multi-party communication with Forward Secrecy and Post-Compromise Security.
 * Based on the MLS (Message Layer Security) defined structure.
 */
class TreeKem {
public:
    static constexpr size_t NODE_SECRET_SIZE = 32;
    static constexpr size_t PUBLIC_KEY_SIZE = 32;

    struct Node {
        uint32_t index;
        std::vector<uint8_t> public_key;
        std::vector<uint8_t> secret; // Optional, only populated for nodes in our direct path
        std::vector<uint8_t> parent_hash;
        bool is_blank = true;
    };

    struct UpdatePathNode {
        std::vector<uint8_t> public_key;
        std::vector<std::vector<uint8_t>> encrypted_path_secrets;
    };

    struct UpdatePath {
        uint32_t leaf_index;
        std::vector<UpdatePathNode> nodes;
    };

    TreeKem();
    ~TreeKem();

    /**
     * @brief Initialize a new tree with just ourselves.
     */
    void init_creator(std::span<const uint8_t, NODE_SECRET_SIZE> leaf_secret);

    /**
     * @brief Add a member to the tree.
     * Returns true if successful. Modifies tree structure.
     */
    bool add_member(std::span<const uint8_t, PUBLIC_KEY_SIZE> member_pub_key);

    /**
     * @brief Remove a member from the tree by their leaf index.
     * Blanks their path.
     */
    bool remove_member(uint32_t leaf_index);

    /**
     * @brief Process an update path from another member.
     */
    bool process_update_path(const UpdatePath& path);

    /**
     * @brief Generate an update path reflecting our new key material.
     * @param out_path Output path variable.
     * @param new_leaf_secret The new secret to seed the path.
     */
    bool generate_update_path(UpdatePath& out_path, std::span<const uint8_t, NODE_SECRET_SIZE> new_leaf_secret);

    /**
     * @brief Get the root group epoch secret derived from the top of the tree.
     */
    std::vector<uint8_t> get_epoch_secret() const;

private:
    struct Impl;
    std::unique_ptr<Impl> pimpl_;
};

} // namespace nit::crypto::osnova
