#pragma once

#include <vector>
#include <string>
#include <cstdint>
#include <memory>

namespace nit::osnova::net {

/**
 * @brief Tor-style Onion Router Node.
 * Provides deep metadata obfuscation for censorship evasion. 
 * Successive layers of encryption mean nodes only know their immediate 
 * predecessor and successor.
 */
class OnionRouter {
public:
    struct CircuitNode {
        std::vector<uint8_t> public_key;
        std::string address;
    };

    OnionRouter();
    ~OnionRouter();

    /**
     * @brief Build an onion-encrypted payload that gets unwrapped node by node.
     * @param payload Final inner payload to deliver to destination.
     * @param circuit The strict ordered path of nodes to traverse.
     * @return Fully encrypted onion packet to be sent to circuit[0].
     */
    std::vector<uint8_t> create_onion(const std::vector<uint8_t>& payload, const std::vector<CircuitNode>& circuit);

    /**
     * @brief Called by intermediate relays.
     * Peels one layer of encryption and returns the payload to route forward.
     */
    std::vector<uint8_t> peel_layer(const std::vector<uint8_t>& current_onion, const std::vector<uint8_t>& local_private_key, std::string& out_next_hop);
};

} // namespace nit::osnova::net
