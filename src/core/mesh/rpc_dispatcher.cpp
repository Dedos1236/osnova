#include "rpc_dispatcher.h"
#include <iostream>

namespace nit::osnova::mesh::rpc {

RpcDispatcher::RpcDispatcher() {
    // Register default handlers or behaviors if any
}

RpcDispatcher::~RpcDispatcher() = default;

std::shared_ptr<RpcObject> RpcDispatcher::create_object_by_type(uint32_t type_id) {
    switch (type_id) {
        case 0x05162463: return std::make_shared<RpcResPQ>();
        case 0xd712e4be: return std::make_shared<RpcReqDHParams>();
        case 0xd0e8075c: return std::make_shared<RpcServerDHParamsOk>();
        case 0x7abe77ec: return std::make_shared<RpcPing>();
        case 0x347773c5: return std::make_shared<RpcPong>();
        case 0x933d1326: return std::make_shared<User>();
        case 0x44f9b43d: return std::make_shared<Message>();
        case 0xc0a08e1e: return std::make_shared<RpcSendMessage>();
        default: return nullptr;
    }
}

bool RpcDispatcher::dispatch(std::span<const uint8_t> payload) {
    if (payload.size() < 4) return false;

    // Read the type ID (Little Endian as per our schema convention)
    serialize::ReadStream stream(payload);
    uint32_t type_id;
    if (!stream.read_u32(type_id)) return false;

    // We reset the stream and let the object decode itself fully
    auto it = handlers_.find(type_id);
    if (it != handlers_.end()) {
        auto obj = create_object_by_type(type_id);
        if (obj) {
            size_t bytes_read = 0;
            if (obj->deserialize(payload, bytes_read)) {
                it->second(obj);
                return true;
            } else {
                std::cerr << "Failed to deserialize RPC object type " << std::hex << type_id << std::endl;
            }
        }
    } else {
        std::cerr << "No handler registered for RPC type: " << std::hex << type_id << std::endl;
    }

    return false;
}

} // namespace nit::osnova::mesh::rpc
