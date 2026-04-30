#pragma once

#include <string>
#include <vector>
#include <cstdint>
#include <map>

namespace nit::osnova::net {

/**
 * @brief TURN Client (Traversal Using Relays around NAT).
 * RFC 5766 implementation for relaying traffic when peer-to-peer 
 * STUN traversal fails.
 */
class TurnClient {
public:
    struct Config {
        std::string username;
        std::string password;
        std::string realm;
        std::string nonce;
    };

    TurnClient(const Config& config);
    ~TurnClient();

    /**
     * @brief Build an Allocate Request.
     */
    std::vector<uint8_t> build_allocate_request();

    /**
     * @brief Parse an Allocate Response. Returns true if success, populates relayed_address.
     */
    bool parse_allocate_response(const std::vector<uint8_t>& data, std::string& out_relayed_ip, uint16_t& out_relayed_port);

    /**
     * @brief Build a CreatePermission Request for a specific peer IP.
     */
    std::vector<uint8_t> build_create_permission(const std::string& peer_ip);

    /**
     * @brief Wrap data in a Send Indication to relay via TURN to a specific peer.
     */
    std::vector<uint8_t> build_send_indication(const std::vector<uint8_t>& payload, const std::string& peer_ip, uint16_t peer_port);

    /**
     * @brief Unwrap a Data Indication received from the TURN relay.
     */
    bool parse_data_indication(const std::vector<uint8_t>& indication, std::vector<uint8_t>& out_payload, std::string& out_peer_ip, uint16_t& out_peer_port);

private:
    Config config_;
    std::vector<uint8_t> current_transaction_id_;

    void attach_integrity(std::vector<uint8_t>& pkt);
};

} // namespace nit::osnova::net
