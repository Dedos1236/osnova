#pragma once

#include <vector>
#include <cstdint>
#include <string>
#include <functional>
#include <memory>

namespace nit::osnova::net {

/**
 * @brief High-performance non-blocking TCP transport (listener and connection).
 */
class TcpTransport {
public:
    using DataCallback = std::function<void(const std::vector<uint8_t>& data)>;
    using ConnectionCallback = std::function<void(std::shared_ptr<TcpTransport> conn)>;

    TcpTransport();
    ~TcpTransport();

    bool listen(const std::string& ip, uint16_t port, ConnectionCallback cb);
    bool connect(const std::string& ip, uint16_t port, std::function<void(bool success)> on_connect);
    
    void start_receive(DataCallback cb);
    bool send(const std::vector<uint8_t>& data);

private:
    struct Impl;
    std::unique_ptr<Impl> impl_;
};

} // namespace nit::osnova::net
