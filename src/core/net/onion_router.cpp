#include "onion_router.h"
#include "../crypto/ecies.h"
#include <cstring>

namespace nit::osnova::net {

OnionRouter::OnionRouter() = default;
OnionRouter::~OnionRouter() = default;

std::vector<uint8_t> OnionRouter::create_onion(const std::vector<uint8_t>& payload, const std::vector<CircuitNode>& circuit) {
    if (circuit.empty()) return payload;

    std::vector<uint8_t> current_blob = payload;

    // Encrypt backwards from dest up to the first hop.
    for (int i = static_cast<int>(circuit.size()) - 1; i >= 0; --i) {
        std::vector<uint8_t> layer;
        
        // Include routing info for the relay: length 64 bytes (Core IP or Node ID string)
        std::string next_hop = (i == static_cast<int>(circuit.size()) - 1) ? "FINAL" : circuit[i+1].address;
        std::vector<uint8_t> route_data(64, 0);
        std::memcpy(route_data.data(), next_hop.c_str(), std::min<size_t>(64, next_hop.size()));

        std::vector<uint8_t> pack;
        pack.insert(pack.end(), route_data.begin(), route_data.end());
        pack.insert(pack.end(), current_blob.begin(), current_blob.end());

        // Encrypt with ECIES -> recipient=circuit[i].public_key
        crypto::osnova::Ecies::encrypt(
            layer,
            std::span<const uint8_t, 32>(circuit[i].public_key.data(), 32),
            pack);

        current_blob = layer;
    }

    return current_blob;
}

std::vector<uint8_t> OnionRouter::peel_layer(const std::vector<uint8_t>& current_onion, const std::vector<uint8_t>& local_private_key, std::string& out_next_hop) {
    std::vector<uint8_t> decrypted;
    if (!crypto::osnova::Ecies::decrypt(
        decrypted,
        std::span<const uint8_t, 32>(local_private_key.data(), 32),
        current_onion)) 
    {
        return {};
    }

    if (decrypted.size() < 64) return {};

    // First 64 bytes are the routing instructions
    out_next_hop = std::string(reinterpret_cast<char*>(decrypted.data()));
    
    // Remaining is the stripped payload for the next hop
    return std::vector<uint8_t>(decrypted.begin() + 64, decrypted.end());
}

} // namespace nit::osnova::net
