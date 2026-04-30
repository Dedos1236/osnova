#pragma once

#include "rpc_schema.h"
#include <functional>
#include <unordered_map>
#include <memory>
#include <vector>

namespace nit::osnova::mesh::rpc {

/**
 * @brief Handles dispatching of incoming OSNOVA RPC messages to appropriate local handlers.
 */
class RpcDispatcher {
public:
    using HandlerFunc = std::function<void(const std::shared_ptr<RpcObject>&)>;

    RpcDispatcher();
    ~RpcDispatcher();

    /**
     * @brief Register a handler for a specific RPC object type.
     */
    template<typename T>
    void register_handler(std::function<void(const std::shared_ptr<T>&)> handler) {
        uint32_t type_id = T().get_type_id();
        handlers_[type_id] = [handler](const std::shared_ptr<RpcObject>& obj) {
            handler(std::static_pointer_cast<T>(obj));
        };
    }

    /**
     * @brief Process an incoming raw binary RPC message payload.
     * Decodes the object and dispatches it to the registered handler.
     */
    bool dispatch(std::span<const uint8_t> payload);

private:
    std::unordered_map<uint32_t, HandlerFunc> handlers_;

    std::shared_ptr<RpcObject> create_object_by_type(uint32_t type_id);
};

} // namespace nit::osnova::mesh::rpc
