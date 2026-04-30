#include "stun_client.h"
#include "../crypto/secure_random.h"
#include <cstring>
#include <arpa/inet.h>

namespace nit::osnova::net {

constexpr uint16_t STUN_BINDING_REQUEST = 0x0001;
constexpr uint16_t STUN_BINDING_RESPONSE = 0x0101;
constexpr uint32_t STUN_MAGIC_COOKIE = 0x2112A442;

StunClient::StunClient() = default;
StunClient::~StunClient() = default;

std::vector<uint8_t> StunClient::build_binding_request() {
    std::vector<uint8_t> pkt(20, 0); // STUN Header size

    // Message Type
    uint16_t type = htons(STUN_BINDING_REQUEST);
    std::memcpy(&pkt[0], &type, 2);

    // Message Length (0 for raw request)
    uint16_t len = 0;
    std::memcpy(&pkt[2], &len, 2);

    // Magic Cookie
    uint32_t cookie = htonl(STUN_MAGIC_COOKIE);
    std::memcpy(&pkt[4], &cookie, 4);

    // Transaction ID (12 bytes)
    crypto::osnova::SecureRandom::get_instance().generate(std::span<uint8_t>(&pkt[8], 12));

    return pkt;
}

bool StunClient::parse_binding_response(const std::vector<uint8_t>& data, Endpoint& out_mapped_address) {
    if (data.size() < 20) return false;

    uint16_t type;
    std::memcpy(&type, &data[0], 2);
    if (ntohs(type) != STUN_BINDING_RESPONSE) return false;

    uint16_t len;
    std::memcpy(&len, &data[2], 2);
    len = ntohs(len);

    if (data.size() < 20 + len) return false;

    size_t offset = 20;
    while (offset + 4 <= 20 + len) {
        uint16_t attr_type, attr_len;
        std::memcpy(&attr_type, &data[offset], 2);
        std::memcpy(&attr_len, &data[offset+2], 2);
        attr_type = ntohs(attr_type);
        attr_len = ntohs(attr_len);

        offset += 4;
        
        if (attr_type == 0x0020) { // XOR-MAPPED-ADDRESS
            if (attr_len >= 8 && offset + attr_len <= data.size()) {
                uint8_t family = data[offset + 1];
                uint16_t port;
                std::memcpy(&port, &data[offset+2], 2);
                port = ntohs(port) ^ (STUN_MAGIC_COOKIE >> 16);

                if (family == 0x01) { // IPv4
                    uint32_t ip;
                    std::memcpy(&ip, &data[offset+4], 4);
                    ip = ntohl(ip) ^ STUN_MAGIC_COOKIE;
                    
                    char ip_str[INET_ADDRSTRLEN];
                    uint32_t net_ip = htonl(ip);
                    inet_ntop(AF_INET, &net_ip, ip_str, INET_ADDRSTRLEN);

                    out_mapped_address.ip = ip_str;
                    out_mapped_address.port = port;
                    return true;
                } else if (family == 0x02 && attr_len >= 20) { // IPv6
                    uint8_t ip6_bytes[16];
                    std::memcpy(ip6_bytes, &data[offset+4], 16);
                    
                    // XOR first 4 bytes with magic cookie
                    uint32_t mc_net = htonl(STUN_MAGIC_COOKIE);
                    for (int i = 0; i < 4; ++i) {
                        ip6_bytes[i] ^= reinterpret_cast<uint8_t*>(&mc_net)[i];
                    }
                    // XOR remaining 12 bytes with transaction ID
                    for (int i = 0; i < 12; ++i) {
                        ip6_bytes[i + 4] ^= data[8 + i];
                    }
                    
                    char ip_str[INET6_ADDRSTRLEN];
                    inet_ntop(AF_INET6, ip6_bytes, ip_str, INET6_ADDRSTRLEN);
                    
                    out_mapped_address.ip = ip_str;
                    out_mapped_address.port = port;
                    return true;
                }
            }
        }
        
        offset += attr_len;
        // Padding
        if (offset % 4 != 0) offset += (4 - (offset % 4));
    }

    return false;
}

} // namespace nit::osnova::net
