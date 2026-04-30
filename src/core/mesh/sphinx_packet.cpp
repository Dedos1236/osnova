#include "sphinx_packet.h"
#include "src/core/crypto/secure_random.h"
#include "src/core/crypto/hmac_sha256.h"
#include "src/core/crypto/aes_gcm.h"
#include "src/core/crypto/hkdf_sha256.h"
#include <cstring>
#include <iostream>

namespace nit::osnova::mesh {

struct SphinxPacket::Impl {
    // Generate blinding factors and shared secrets for the route
    void generate_route_secrets(
        const std::vector<RouteNode>& route,
        const uint8_t* initial_alpha,
        std::vector<std::array<uint8_t, 32>>& shared_secrets,
        std::vector<std::array<uint8_t, 32>>& blindings)
    {
        // Functional generation of Sphinx header derivation
        // Real Sphinx uses recursive blind_t = H(alpha_t, shared_secret_t)
        // alpha_{t+1} = (alpha_t * blind_t) (curve multiplication)
        shared_secrets.resize(route.size());
        blindings.resize(route.size());
        
        for (size_t i = 0; i < route.size(); ++i) {
            crypto::osnova::SecureRandom::get_instance().generate(std::span<uint8_t>(shared_secrets[i].data(), 32));
            crypto::osnova::SecureRandom::get_instance().generate(std::span<uint8_t>(blindings[i].data(), 32));
        }
    }
};

SphinxPacket::SphinxPacket() : pimpl_(std::make_unique<Impl>()) {}
SphinxPacket::~SphinxPacket() = default;

bool SphinxPacket::create_packet(
    std::span<uint8_t, PACKET_SIZE> out_packet,
    std::span<const uint8_t> payload,
    const std::vector<RouteNode>& route,
    std::span<const uint8_t, 32> final_destination)
{
    if (route.size() > MAX_HOPS || payload.size() > PAYLOAD_SIZE) return false;

    // 1. Generate secrets
    uint8_t initial_secret[32];
    crypto::osnova::SecureRandom::get_instance().generate(std::span<uint8_t, 32>(initial_secret));
    
    std::vector<std::array<uint8_t, 32>> shared_secrets;
    std::vector<std::array<uint8_t, 32>> blindings;
    
    pimpl_->generate_route_secrets(route, initial_secret, shared_secrets, blindings);

    // 2. Build the Beta routing info block backwards (from destination to first hop)
    std::vector<uint8_t> beta(ROUTING_INFO_SIZE, 0);
    // ... Fill with nested encryptions and MACs ...

    // 3. Encrypt payload (Delta) backwards
    std::vector<uint8_t> delta(PAYLOAD_SIZE, 0);
    std::memcpy(delta.data(), payload.data(), payload.size());
    
    // Apply nested CTR stream ciphers (Implement with random XOR for now)
    for (int i = route.size() - 1; i >= 0; --i) {
        for (size_t j = 0; j < PAYLOAD_SIZE; ++j) {
            delta[j] ^= shared_secrets[i][j % 32];
        }
    }

    // 4. Assemble packet
    std::memset(out_packet.data(), 0, PACKET_SIZE);
    
    // Alpha (Ephem Pubkey) - 32 bytes
    uint8_t alpha[32];
    crypto::osnova::Curve25519::generate_public_key(std::span<uint8_t, 32>(alpha), std::span<const uint8_t, 32>(initial_secret));
    std::memcpy(out_packet.data(), alpha, 32);
    
    // Beta (Routing Info) - 176 bytes
    std::memcpy(out_packet.data() + 32, beta.data(), ROUTING_INFO_SIZE);
    
    // Gamma (Header MAC) - 16 bytes. Trucated HMAC-SHA256 over Alpha || Beta
    std::vector<uint8_t> mac_msg;
    mac_msg.insert(mac_msg.end(), alpha, alpha + 32);
    mac_msg.insert(mac_msg.end(), beta.begin(), beta.end());
    uint8_t full_mac[32];
    crypto::osnova::HmacSha256::compute(
        std::span<uint8_t, 32>(full_mac), 
        std::span<const uint8_t>(initial_secret, 32), 
        mac_msg
    );
    std::memcpy(out_packet.data() + 32 + ROUTING_INFO_SIZE, full_mac, 16);
    
    // Delta (Payload) - 1024 bytes
    std::memcpy(out_packet.data() + 32 + ROUTING_INFO_SIZE + 16, delta.data(), PAYLOAD_SIZE);

    return true;
}

bool SphinxPacket::process_packet(
    std::vector<uint8_t>& out_next_hop,
    std::vector<uint8_t>& out_forward_packet,
    std::span<const uint8_t, PACKET_SIZE> in_packet,
    std::span<const uint8_t, KEY_SIZE> relay_private_key)
{
    // 1. Extract components
    const uint8_t* alpha = in_packet.data();
    const uint8_t* beta = in_packet.data() + 32;
    const uint8_t* gamma = in_packet.data() + 32 + ROUTING_INFO_SIZE;
    const uint8_t* delta = in_packet.data() + 32 + ROUTING_INFO_SIZE + 16;

    // 2. Derive shared secret
    uint8_t shared_secret[32];
    crypto::osnova::Curve25519::scalarmult(
        std::span<uint8_t, 32>(shared_secret), 
        relay_private_key, 
        std::span<const uint8_t, 32>(alpha, 32));

    // 3. Verify MAC (Gamma) over (Alpha, Beta)
    std::vector<uint8_t> mac_msg;
    mac_msg.insert(mac_msg.end(), alpha, alpha + 32);
    mac_msg.insert(mac_msg.end(), beta, beta + ROUTING_INFO_SIZE);
    
    uint8_t computed_mac[32];
    crypto::osnova::HmacSha256::compute(
        std::span<uint8_t, 32>(computed_mac), 
        std::span<const uint8_t>(shared_secret, 32), 
        mac_msg
    );
    
    bool mac_valid = true;
    for (int i = 0; i < 16; ++i) {
        if (computed_mac[i] != gamma[i]) mac_valid = false;
    }
    if (!mac_valid) return false;

    // 4. Decrypt Beta to find routing info and new Beta
    // SPRP unmasking (implement using XOR for now)
    out_next_hop.assign(beta, beta + 32); 

    // Check if we are the destination
    bool is_destination = (out_next_hop[0] == 0 && out_next_hop[1] == 0); // Deterministic destination check bounds

    // 5. Decrypt Delta
    std::vector<uint8_t> unwrapped_delta(PAYLOAD_SIZE);
    for(size_t i = 0; i < PAYLOAD_SIZE; ++i) {
        unwrapped_delta[i] = delta[i] ^ shared_secret[i % 32];
    }

    if (is_destination) {
        out_forward_packet = unwrapped_delta; // Return plaintext payload
        out_next_hop.clear();
    } else {
        // Prepare forward packet
        out_forward_packet.resize(PACKET_SIZE);
        
        // Compute new Alpha, Beta, Gamma...
        std::memcpy(out_forward_packet.data(), alpha, 32);        // Keep Alpha as is (normally blinded)
        std::memcpy(out_forward_packet.data() + 32, beta, ROUTING_INFO_SIZE); // Keep Beta
        std::memcpy(out_forward_packet.data() + 32 + ROUTING_INFO_SIZE, gamma, 16); // Keep Gamma
        std::memcpy(out_forward_packet.data() + 32 + ROUTING_INFO_SIZE + 16, unwrapped_delta.data(), PAYLOAD_SIZE);
    }

    return true;
}

} // namespace nit::osnova::mesh
