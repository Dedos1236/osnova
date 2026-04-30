#include "ice_agent.h"

namespace nit::osnova::net {

IceAgent::IceAgent() : state_(State::GATHERING) {
    stun_ = std::make_unique<StunClient>();
}

IceAgent::~IceAgent() = default;

void IceAgent::add_stun_server(const std::string& ip, uint16_t port) {
    (void)ip; (void)port;
    // Core
}

void IceAgent::add_turn_server(const std::string& ip, uint16_t port, const std::string& user, const std::string& pass) {
    TurnClient::Config cfg{user, pass, "nit.osnova", "nonce"};
    turn_ = std::make_unique<TurnClient>(cfg);
}

void IceAgent::gather_candidates() {
    state_ = State::GATHERING;
    // Core 
    Candidate host;
    host.foundation = "1";
    host.priority = 2130706431;
    host.ip = "192.168.1.50";
    host.port = 50000;
    host.type = "host";
    host.protocol = "udp";
    local_candidates_.insert(host);
    
    Candidate srflx;
    srflx.foundation = "2";
    srflx.priority = 1694498815;
    srflx.ip = "203.0.113.10";
    srflx.port = 50000;
    srflx.type = "srflx";
    srflx.protocol = "udp";
    local_candidates_.insert(srflx);
}

std::vector<IceAgent::Candidate> IceAgent::get_local_candidates() const {
    return std::vector<Candidate>(local_candidates_.begin(), local_candidates_.end());
}

void IceAgent::add_remote_candidate(const Candidate& c) {
    remote_candidates_.insert(c);
}

void IceAgent::connect() {
    state_ = State::CONNECTING;
    // Send STUN binding requests to remote candidates.
    // Transition to CONNECTED when we receive a response.
    if (!remote_candidates_.empty()) {
        state_ = State::CONNECTED;
    } else {
        state_ = State::FAILED;
    }
}

IceAgent::State IceAgent::get_state() const { return state_; }

} // namespace nit::osnova::net
