#pragma once

#include "stun_client.h"
#include "turn_client.h"
#include <string>
#include <vector>
#include <functional>
#include <memory>
#include <set>

namespace nit::osnova::net {

/**
 * @brief Interactive Connectivity Establishment (ICE).
 * Orchestrates STUN and TURN to find the best peer-to-peer connection path.
 */
class IceAgent {
public:
    enum class State {
        GATHERING,
        CONNECTING,
        CONNECTED,
        FAILED
    };

    struct Candidate {
        std::string foundation;
        uint32_t priority;
        std::string ip;
        uint16_t port;
        std::string type; // "host", "srflx", "relay"
        std::string protocol; // "udp", "tcp"
        
        bool operator<(const Candidate& other) const {
            return priority > other.priority; // higher priority first
        }
    };

    IceAgent();
    ~IceAgent();

    void add_stun_server(const std::string& ip, uint16_t port);
    void add_turn_server(const std::string& ip, uint16_t port, const std::string& user, const std::string& pass);
    
    void gather_candidates();
    std::vector<Candidate> get_local_candidates() const;
    
    void add_remote_candidate(const Candidate& c);
    void connect();

    State get_state() const;

private:
    State state_;
    std::set<Candidate> local_candidates_;
    std::set<Candidate> remote_candidates_;
    
    std::unique_ptr<StunClient> stun_;
    std::unique_ptr<TurnClient> turn_;
};

} // namespace nit::osnova::net
