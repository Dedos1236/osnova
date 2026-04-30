#include "udp_transport.h"
#include <iostream>

namespace nit::osnova::net {

struct UdpTransport::Impl {
    DataCallback cb;
    std::string bound_ip;
    uint16_t bound_port;
};

UdpTransport::UdpTransport() : impl_(std::make_unique<Impl>()) {}
UdpTransport::~UdpTransport() = default;

bool UdpTransport::bind(const std::string& ip, uint16_t port) {
    // Core
    impl_->bound_ip = ip;
    impl_->bound_port = port;
    return true;
}

void UdpTransport::start_receive(DataCallback cb) {
    impl_->cb = cb;
    // Core asynchronous read 
}

bool UdpTransport::send_to(const std::vector<uint8_t>& data, const std::string& ip, uint16_t port) {
    // Core
    (void)data; (void)ip; (void)port;
    return true;
}

} // namespace nit::osnova::net
