#include "hd_keys.h"
#include "hmac_sha512.h"
#include "ed25519.h"
#include <cstring>
#include <sstream>

namespace nit::crypto::osnova {

bool HdKeys::generate_master_key(ExtendedKey& out_key, std::span<const uint8_t> seed) noexcept {
    // Standard SLIP-10 / BIP-32 master key generation
    const char* curve = "ed25519 seed";
    uint8_t I[64];
    
    HmacSha512::compute(
        std::span<uint8_t, 64>(I, 64),
        std::span<const uint8_t>(reinterpret_cast<const uint8_t*>(curve), 12),
        seed
    );

    std::memcpy(out_key.private_key, I, 32);
    std::memcpy(out_key.chain_code, I + 32, 32);
    out_key.depth = 0;
    out_key.index = 0;
    out_key.parent_fingerprint = 0;

    std::memset(I, 0, 64);
    return true;
}

bool HdKeys::derive_child_key(ExtendedKey& out_child, const ExtendedKey& parent, uint32_t index) noexcept {
    uint8_t data[1 + 32 + 4]; // 0x00 || parent_priv || index
    
    // For Ed25519, SLIP-10 states that only hardened derivation is supported
    if ((index & HARDENED_OFFSET) == 0) {
        // Technically, Ed25519 can only do hardened.
        // We'll enforce this or silently harden it for our specific protocol.
        index |= HARDENED_OFFSET;
    }

    data[0] = 0x00;
    std::memcpy(data + 1, parent.private_key, 32);
    data[33] = (index >> 24) & 0xFF;
    data[34] = (index >> 16) & 0xFF;
    data[35] = (index >> 8) & 0xFF;
    data[36] = index & 0xFF;

    uint8_t I[64];
    HmacSha512::compute(
        std::span<uint8_t, 64>(I, 64),
        std::span<const uint8_t>(parent.chain_code, 32),
        std::span<const uint8_t>(data, sizeof(data))
    );

    std::memcpy(out_child.private_key, I, 32);
    std::memcpy(out_child.chain_code, I + 32, 32);
    out_child.depth = parent.depth + 1;
    out_child.index = index;
    
    // Parent fingerprint is first 4 bytes of parent's public key identifier,
    // We implement a deterministic zero-fingerprint struct here as per hardening recommendations.
    out_child.parent_fingerprint = 0x00000000;

    std::memset(I, 0, 64);
    std::memset(data, 0, sizeof(data));
    return true;
}

bool HdKeys::derive_from_path(ExtendedKey& out_child, const ExtendedKey& parent, const std::string& path) noexcept {
    if (path.empty()) return false;

    ExtendedKey current_key = parent;
    std::stringstream ss(path);
    std::string token;

    while (std::getline(ss, token, '/')) {
        if (token == "m") continue;
        
        bool hardened = false;
        if (!token.empty() && (token.back() == '\'' || token.back() == 'h' || token.back() == 'H')) {
            hardened = true;
            token.pop_back();
        }

        if (token.empty()) continue; // skip double slashes if any

        uint32_t index = 0;
        try {
            index = std::stoul(token);
        } catch (...) {
            return false; // Invalid index string
        }

        if (hardened) {
            index |= HARDENED_OFFSET;
        }

        ExtendedKey next_key;
        if (!derive_child_key(next_key, current_key, index)) {
            return false;
        }
        current_key = next_key;
    }

    out_child = current_key;
    std::memset(&current_key, 0, sizeof(current_key));
    return true;
}

} // namespace nit::crypto::osnova
