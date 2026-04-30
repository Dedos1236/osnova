#pragma once

#include <cstdint>
#include <span>
#include <vector>
#include <string>

namespace nit::crypto::osnova {

/**
 * @brief Hierarchical Deterministic (HD) Key Derivation.
 * Allows creating a tree of keys from a single master seed (similar to BIP32/SLIP10).
 * Specifically core for Ed25519 and Curve25519 keys for the OSNOVA network.
 */
class HdKeys {
public:
    static constexpr size_t CHAIN_CODE_SIZE = 32;
    static constexpr size_t PRIVATE_KEY_SIZE = 32;
    static constexpr uint32_t HARDENED_OFFSET = 0x80000000;

    struct ExtendedKey {
        uint8_t private_key[PRIVATE_KEY_SIZE];
        uint8_t chain_code[CHAIN_CODE_SIZE];
        uint8_t depth;
        uint32_t index;
        uint32_t parent_fingerprint;
    };

    /**
     * @brief Generate the master extended key from a seed value.
     * 
     * @param out_key Output extended key structure
     * @param seed Input seed (typically 32 or 64 bytes)
     * @return true on success
     */
    static bool generate_master_key(
        ExtendedKey& out_key,
        std::span<const uint8_t> seed) noexcept;

    /**
     * @brief Derive a child extended key from a parent extended key.
     * 
     * @param out_child Output derived child key
     * @param parent Input parent key
     * @param index Child index (>= 0x80000000 means hardened derivation)
     * @return true on success
     */
    static bool derive_child_key(
        ExtendedKey& out_child,
        const ExtendedKey& parent,
        uint32_t index) noexcept;

    /**
     * @brief Derive a child key using a path string (e.g. "m/44'/0'/0'/0/0").
     * 
     * @param out_child Output derived key
     * @param parent Input starting key (usually master "m")
     * @param path The derivation path string
     * @return true on success
     */
    static bool derive_from_path(
        ExtendedKey& out_child,
        const ExtendedKey& parent,
        const std::string& path) noexcept;
};

} // namespace nit::crypto::osnova
