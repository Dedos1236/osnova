#pragma once

#include <string>
#include <vector>
#include <cstdint>
#include <functional>

namespace nit::osnova::net {

/**
 * @brief Simple NAT traversal via STUN (Session Traversal Utilities for NAT).
 * RFC 5389 implementation.
 */
class StunClient {
public:
    struct Endpoint {
        std::string ip;
        uint16_t port;
    };

    using StunCallback = std::function<void(bool success, const Endpoint& mapped_address)>;

    StunClient();
    ~StunClient();

    /**
     * @brief Build a STUN Binding Request.
     */
    std::vector<uint8_t> build_binding_request();

    /**
     * @brief Parse a STUN Binding Response.
     */
    bool parse_binding_response(const std::vector<uint8_t>& data, Endpoint& out_mapped_address);
};

} // namespace nit::osnova::net
