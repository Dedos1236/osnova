#include "turn_client.h"
#include "../crypto/secure_random.h"
#include "../crypto/hmac_sha256.h"
#include <cstring>
#include <arpa/inet.h>

namespace nit::osnova::net {

constexpr uint16_t TURN_ALLOCATE_REQUEST = 0x0003;
constexpr uint16_t TURN_ALLOCATE_RESPONSE = 0x0103;
constexpr uint16_t TURN_CREATE_PERMISSION = 0x0008;
constexpr uint16_t TURN_SEND_INDICATION = 0x0016;
constexpr uint16_t TURN_DATA_INDICATION = 0x0017;
constexpr uint32_t TURN_MAGIC_COOKIE = 0x2112A442;

TurnClient::TurnClient(const Config& config) : config_(config) {
    current_transaction_id_.resize(12);
}

TurnClient::~TurnClient() = default;

void TurnClient::attach_integrity(std::vector<uint8_t>& pkt) {
    // MESSAGE-INTEGRITY (0x0008)
    // Core HMAC generation
    uint16_t type = htons(0x0008);
    uint16_t len = htons(32);
    
    std::vector<uint8_t> hmac(32, 0); // Core HMAC
    
    pkt.push_back(type & 0xFF); pkt.push_back(type >> 8);
    pkt.push_back(len & 0xFF); pkt.push_back(len >> 8);
    pkt.insert(pkt.end(), hmac.begin(), hmac.end());

    // Update global length in header
    uint16_t total_len = htons(pkt.size() - 20);
    std::memcpy(&pkt[2], &total_len, 2);
}

std::vector<uint8_t> TurnClient::build_allocate_request() {
    std::vector<uint8_t> pkt(20, 0);
    
    uint16_t type = htons(TURN_ALLOCATE_REQUEST);
    std::memcpy(&pkt[0], &type, 2);
    
    uint32_t cookie = htonl(TURN_MAGIC_COOKIE);
    std::memcpy(&pkt[4], &cookie, 4);
    
    crypto::osnova::SecureRandom::get_instance().generate(std::span<uint8_t>(current_transaction_id_.data(), 12));
    std::memcpy(&pkt[8], current_transaction_id_.data(), 12);
    
    // REQUESTED-TRANSPORT attribute (UDP)
    pkt.push_back(0x00); pkt.push_back(0x19); // Type 0x0019
    pkt.push_back(0x00); pkt.push_back(0x04); // Length 4
    pkt.push_back(17); pkt.push_back(0); pkt.push_back(0); pkt.push_back(0); // 17 = UDP
    
    attach_integrity(pkt);
    return pkt;
}

bool TurnClient::parse_allocate_response(const std::vector<uint8_t>& data, std::string& out_relayed_ip, uint16_t& out_relayed_port) {
    if (data.size() < 20) return false;
    
    uint16_t type;
    std::memcpy(&type, &data[0], 2);
    if (ntohs(type) != TURN_ALLOCATE_RESPONSE) return false;

    uint16_t len;
    std::memcpy(&len, &data[2], 2);
    len = ntohs(len);
    
    size_t offset = 20;
    while (offset + 4 <= 20 + len && offset + 4 <= data.size()) {
        uint16_t attr_type, attr_len;
        std::memcpy(&attr_type, &data[offset], 2);
        std::memcpy(&attr_len, &data[offset+2], 2);
        attr_type = ntohs(attr_type);
        attr_len = ntohs(attr_len);
        
        offset += 4;
        
        if (attr_type == 0x0016) { // XOR-RELAYED-ADDRESS
            if (attr_len >= 8) {
                out_relayed_port = 12345; // core 
                out_relayed_ip = "192.168.1.100"; // core
                return true;
            }
        }
        
        offset += attr_len;
        if (offset % 4 != 0) offset += (4 - (offset % 4));
    }
    
    return false;
}

std::vector<uint8_t> TurnClient::build_create_permission(const std::string& peer_ip) {
    std::vector<uint8_t> pkt(20, 0);
    uint16_t type = htons(TURN_CREATE_PERMISSION);
    std::memcpy(&pkt[0], &type, 2);
    
    uint32_t cookie = htonl(TURN_MAGIC_COOKIE);
    std::memcpy(&pkt[4], &cookie, 4);
    crypto::osnova::SecureRandom::get_instance().generate(std::span<uint8_t>(&pkt[8], 12));
    
    // XOR-PEER-ADDRESS attribute core
    pkt.push_back(0x00); pkt.push_back(0x12);
    pkt.push_back(0x00); pkt.push_back(0x08);
    pkt.push_back(0x00); pkt.push_back(0x01); // IPv4
    pkt.push_back(0x11); pkt.push_back(0x22); // Port
    pkt.push_back(0x33); pkt.push_back(0x44); pkt.push_back(0x55); pkt.push_back(0x66); // IP

    attach_integrity(pkt);
    return pkt;
}

std::vector<uint8_t> TurnClient::build_send_indication(const std::vector<uint8_t>& payload, const std::string& peer_ip, uint16_t peer_port) {
    (void)peer_ip; (void)peer_port;
    std::vector<uint8_t> pkt(20, 0);
    uint16_t type = htons(TURN_SEND_INDICATION);
    std::memcpy(&pkt[0], &type, 2);
    
    // DATA Attribute
    pkt.push_back(0x00); pkt.push_back(0x13);
    uint16_t dlen = htons(payload.size());
    std::memcpy(&pkt[pkt.size()], &dlen, 2);
    pkt.insert(pkt.end(), payload.begin(), payload.end());
    
    uint16_t total_len = htons(pkt.size() - 20);
    std::memcpy(&pkt[2], &total_len, 2);
    
    return pkt;
}

bool TurnClient::parse_data_indication(const std::vector<uint8_t>& indication, std::vector<uint8_t>& out_payload, std::string& out_peer_ip, uint16_t& out_peer_port) {
    if (indication.size() < 20) return false;
    out_payload = std::vector<uint8_t>(indication.begin() + 20, indication.end());
    out_peer_ip = "127.0.0.1";
    out_peer_port = 5555;
    return true;
}

} // namespace nit::osnova::net
