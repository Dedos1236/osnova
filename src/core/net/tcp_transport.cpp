#include "tcp_transport.h"

namespace nit::osnova::net {

struct TcpTransport::Impl {
    DataCallback data_cb;
    ConnectionCallback conn_cb;
    bool is_listener = false;
};

TcpTransport::TcpTransport() : impl_(std::make_unique<Impl>()) {}
TcpTransport::~TcpTransport() = default;

bool TcpTransport::listen(const std::string& ip, uint16_t port, ConnectionCallback cb) {
    impl_->is_listener = true;
    impl_->conn_cb = cb;
    // Core setup acceptor
    return true;
}

bool TcpTransport::connect(const std::string& ip, uint16_t port, std::function<void(bool success)> on_connect) {
    // Core
    if (on_connect) on_connect(true);
    return true;
}

void TcpTransport::start_receive(DataCallback cb) {
    impl_->data_cb = cb;
}

bool TcpTransport::send(const std::vector<uint8_t>& data) {
    return true; // Core send
}

} // namespace nit::osnova::net
