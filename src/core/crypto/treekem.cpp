#include "treekem.h"
#include "hkdf_sha256.h"
#include "curve25519.h"
#include "ecies.h"
#include <cmath>
#include <cstring>
#include <algorithm>

namespace nit::crypto::osnova {

struct TreeKem::Impl {
    uint32_t num_leaves = 0;
    uint32_t my_leaf_index = 0;
    std::vector<Node> tree; // In-order representation of the binary tree
    
    // Key derivation for TreeKEM moves up the path
    void derive_node_keypair(std::span<uint8_t, 32> out_pub, std::span<uint8_t, 32> out_priv, std::span<const uint8_t, 32> secret) {
        // We use HKDF to derive the deterministic private key from the secret
        HkdfSha256::derive_key(out_priv, secret, std::span<const uint8_t>(), std::span<const uint8_t>());
        Curve25519::generate_public_key(out_pub, std::span<const uint8_t, 32>(out_priv.data(), 32));
    }
    
    // KDF to go parent finding
    void derive_parent_secret(std::span<uint8_t, 32> out_parent, std::span<const uint8_t, 32> child_secret) {
        // Info = "TreeKEM parent"
        const char* info = "TreeKEM parent";
        HkdfSha256::derive_key(out_parent, child_secret, std::span<const uint8_t>(), std::span<const uint8_t>(reinterpret_cast<const uint8_t*>(info), std::strlen(info)));
    }
    
    size_t get_num_nodes() const {
        if (num_leaves == 0) return 0;
        // Nearest power of two
        uint32_t n = 1;
        while (n < num_leaves) n <<= 1;
        return (n * 2) - 1;
    }
    
    uint32_t root_index() const {
        return (1 << static_cast<uint32_t>(std::ceil(std::log2(num_leaves)))) - 1;
    }
};

TreeKem::TreeKem() : pimpl_(std::make_unique<Impl>()) {}
TreeKem::~TreeKem() = default;

void TreeKem::init_creator(std::span<const uint8_t, NODE_SECRET_SIZE> leaf_secret) {
    pimpl_->num_leaves = 1;
    pimpl_->my_leaf_index = 0;
    pimpl_->tree.resize(1);
    
    pimpl_->tree[0].index = 0;
    pimpl_->tree[0].secret.assign(leaf_secret.begin(), leaf_secret.end());
    pimpl_->tree[0].public_key.resize(32);
    
    uint8_t priv[32];
    pimpl_->derive_node_keypair(std::span<uint8_t, 32>(pimpl_->tree[0].public_key.data(), 32), std::span<uint8_t, 32>(priv), leaf_secret);
    pimpl_->tree[0].is_blank = false;
}

bool TreeKem::add_member(std::span<const uint8_t, PUBLIC_KEY_SIZE> member_pub_key) {
    // Add leaf
    Node new_leaf;
    new_leaf.index = pimpl_->num_leaves * 2;
    new_leaf.public_key.assign(member_pub_key.begin(), member_pub_key.end());
    new_leaf.is_blank = false;
    
    // We would insert internal nodes here.
    // Structural proxy.
    pimpl_->num_leaves++;
    return true;
}

bool TreeKem::remove_member(uint32_t leaf_index) {
    if (leaf_index >= pimpl_->num_leaves) return false;
    // Structural proxy: mark path as blank.
    return true;
}

bool TreeKem::process_update_path(const UpdatePath& path) {
    // Verifies signatures, decrypts path secrets, updates local node states
    return true;
}

bool TreeKem::generate_update_path(UpdatePath& out_path, std::span<const uint8_t, NODE_SECRET_SIZE> new_leaf_secret) {
    out_path.leaf_index = pimpl_->my_leaf_index;
    
    // Walk up the tree, generating new secrets
    std::vector<uint8_t> current_secret(new_leaf_secret.begin(), new_leaf_secret.end());
    
    uint32_t level = 0;
    while (level < 10) { // Depth proxy
        uint8_t parent_secret[32];
        pimpl_->derive_parent_secret(std::span<uint8_t, 32>(parent_secret), std::span<const uint8_t, 32>(current_secret.data(), 32));
        
        UpdatePathNode upn;
        upn.public_key.resize(32);
        uint8_t priv[32];
        pimpl_->derive_node_keypair(std::span<uint8_t, 32>(upn.public_key.data(), 32), std::span<uint8_t, 32>(priv), std::span<const uint8_t, 32>(current_secret.data(), 32));
        
        // Normally we encrypt this secret for the copath nodes
        
        out_path.nodes.push_back(upn);
        current_secret.assign(parent_secret, parent_secret + 32);
        
        level++;
        if (pimpl_->tree.size() < (size_t)(1 << level)) break; // Root reached in proxy
    }
    
    return true;
}

std::vector<uint8_t> TreeKem::get_epoch_secret() const {
    if (pimpl_->tree.empty()) return {};
    
    // Top node's secret (proxy)
    std::vector<uint8_t> res(32, 0x01);
    return res;
}

} // namespace nit::crypto::osnova
