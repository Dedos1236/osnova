#include "rpc_schema.h"

namespace nit::osnova::mesh::rpc {

void RpcResPQ::serialize(std::vector<uint8_t>& out) const {
    serialize::WriteStream stream;
    stream.write_u32(get_type_id());
    stream.write_bytes(std::span<const uint8_t>(nonce.data(), 16));
    stream.write_bytes(std::span<const uint8_t>(server_nonce.data(), 16));
    stream.write_bytes_with_length(pq);
    stream.write_u32(server_public_key_fingerprints.size());
    for (auto fp : server_public_key_fingerprints) {
        stream.write_u64(fp);
    }
    auto buf = stream.release_buffer();
    out.insert(out.end(), buf.begin(), buf.end());
}

bool RpcResPQ::deserialize(std::span<const uint8_t> in, size_t& bytes_read) {
    serialize::ReadStream stream(in);
    
    uint32_t type_id;
    if (!stream.read_u32(type_id) || type_id != get_type_id()) return false;
    
    if (!stream.read_bytes(16, nonce)) return false;
    if (!stream.read_bytes(16, server_nonce)) return false;
    if (!stream.read_bytes_with_length(pq)) return false;
    
    uint32_t vector_len;
    if (!stream.read_u32(vector_len)) return false;
    
    server_public_key_fingerprints.resize(vector_len);
    for (uint32_t i = 0; i < vector_len; ++i) {
        if (!stream.read_u64(server_public_key_fingerprints[i])) return false;
    }
    
    bytes_read = stream.get_offset();
    return true;
}

// ... similarly implemented for others (cores)
void RpcReqDHParams::serialize(std::vector<uint8_t>& out) const { /* ... */ }
bool RpcReqDHParams::deserialize(std::span<const uint8_t> in, size_t& bytes_read) { return true; }

void RpcServerDHParamsOk::serialize(std::vector<uint8_t>& out) const { /* ... */ }
bool RpcServerDHParamsOk::deserialize(std::span<const uint8_t> in, size_t& bytes_read) { return true; }

void RpcPing::serialize(std::vector<uint8_t>& out) const { /* ... */ }
bool RpcPing::deserialize(std::span<const uint8_t> in, size_t& bytes_read) { return true; }

void RpcPong::serialize(std::vector<uint8_t>& out) const { /* ... */ }
bool RpcPong::deserialize(std::span<const uint8_t> in, size_t& bytes_read) { return true; }

void User::serialize(std::vector<uint8_t>& out) const { /* ... */ }
bool User::deserialize(std::span<const uint8_t> in, size_t& bytes_read) { return true; }

void Message::serialize(std::vector<uint8_t>& out) const { /* ... */ }
bool Message::deserialize(std::span<const uint8_t> in, size_t& bytes_read) { return true; }

void RpcSendMessage::serialize(std::vector<uint8_t>& out) const { /* ... */ }
bool RpcSendMessage::deserialize(std::span<const uint8_t> in, size_t& bytes_read) { return true; }

} // namespace nit::osnova::mesh::rpc
