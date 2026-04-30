#pragma once

#include "serialize.h"
#include <string>
#include <vector>
#include <memory>
#include <optional>

namespace nit::osnova::mesh::rpc {

// ============================================================================
// OSNOVA RPC TYPE DEFINITIONS AND CONSTRUCTORS (MIMICS MTPROTO TL-SCHEMA)
// ============================================================================

// Base generic Object type
struct RpcObject : public serialize::Serializable {
    virtual ~RpcObject() = default;
};

// --- Layer 1: Cryptographic Primitives ---

struct RpcResPQ : public RpcObject {
    uint32_t get_type_id() const override { return 0x05162463; }
    
    std::vector<uint8_t> nonce; // 16 bytes
    std::vector<uint8_t> server_nonce; // 16 bytes
    std::vector<uint8_t> pq; // bytes
    std::vector<uint64_t> server_public_key_fingerprints;
    
    void serialize(std::vector<uint8_t>& out) const override;
    bool deserialize(std::span<const uint8_t> in, size_t& bytes_read) override;
};

struct RpcReqDHParams : public RpcObject {
    uint32_t get_type_id() const override { return 0xd712e4be; }
    
    std::vector<uint8_t> nonce; // 16 bytes
    std::vector<uint8_t> server_nonce; // 16 bytes
    std::vector<uint8_t> p; 
    std::vector<uint8_t> q; 
    uint64_t public_key_fingerprint = 0;
    std::vector<uint8_t> encrypted_data; // encrypted DH inner data
    
    void serialize(std::vector<uint8_t>& out) const override;
    bool deserialize(std::span<const uint8_t> in, size_t& bytes_read) override;
};

struct RpcServerDHParamsOk : public RpcObject {
    uint32_t get_type_id() const override { return 0xd0e8075c; }
    
    std::vector<uint8_t> nonce;
    std::vector<uint8_t> server_nonce;
    std::vector<uint8_t> encrypted_answer;
    
    void serialize(std::vector<uint8_t>& out) const override;
    bool deserialize(std::span<const uint8_t> in, size_t& bytes_read) override;
};

// --- Layer 2: Network Primitives ---

struct RpcPing : public RpcObject {
    uint32_t get_type_id() const override { return 0x7abe77ec; }
    
    uint64_t ping_id = 0;
    
    void serialize(std::vector<uint8_t>& out) const override;
    bool deserialize(std::span<const uint8_t> in, size_t& bytes_read) override;
};

struct RpcPong : public RpcObject {
    uint32_t get_type_id() const override { return 0x347773c5; }
    
    uint64_t msg_id = 0;
    uint64_t ping_id = 0;
    
    void serialize(std::vector<uint8_t>& out) const override;
    bool deserialize(std::span<const uint8_t> in, size_t& bytes_read) override;
};

// --- Layer 3: Application Entities ---

struct User : public RpcObject {
    uint32_t get_type_id() const override { return 0x933d1326; } // user profile
    
    uint32_t flags = 0;
    uint64_t id = 0;
    std::optional<std::string> first_name;
    std::optional<std::string> last_name;
    std::optional<std::string> username;
    std::optional<std::string> phone;
    
    void serialize(std::vector<uint8_t>& out) const override;
    bool deserialize(std::span<const uint8_t> in, size_t& bytes_read) override;
};

struct Message : public RpcObject {
    uint32_t get_type_id() const override { return 0x44f9b43d; }
    
    uint32_t flags = 0;
    uint64_t id = 0;
    uint64_t from_id = 0;
    uint64_t peer_id = 0;
    uint32_t date = 0;
    std::string message;
    
    void serialize(std::vector<uint8_t>& out) const override;
    bool deserialize(std::span<const uint8_t> in, size_t& bytes_read) override;
};

struct RpcSendMessage : public RpcObject {
    uint32_t get_type_id() const override { return 0xc0a08e1e; }
    
    uint64_t peer_id = 0;
    std::string message;
    uint64_t random_id = 0;
    
    void serialize(std::vector<uint8_t>& out) const override;
    bool deserialize(std::span<const uint8_t> in, size_t& bytes_read) override;
};

} // namespace nit::osnova::mesh::rpc
