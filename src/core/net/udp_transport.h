#pragma once

#include <vector>
#include <cstdint>
#include <string>
#include <functional>
#include <memory>

namespace nit::osnova::net {

/**
 * @brief High-performance non-blocking UDP wrapper.
 */
class UdpTransport {
public:
    using DataCallback = std::function<void(const std::vector<uint8_t>& data, const std::string& remote_ip, uint16_t remote_port)>;

    UdpTransport();
    ~UdpTransport();

    bool bind(const std::string& ip, uint16_t port);
    void start_receive(DataCallback cb);
    bool send_to(const std::vector<uint8_t>& data, const std::string& ip, uint16_t port);

private:
    struct Impl;
    std::unique_ptr<Impl> impl_;
};

} // namespace nit::osnova::net
