#pragma once

#include <string>
#include <vector>
#include <cstdint>

namespace nit::osnova::media {

/**
 * @brief Interactive Connectivity Establishment (ICE).
 * Used for NAT traversal in OSNOVA WebRTC and P2P mesh logic.
 * Combines STUN and TURN protocols to find the best peer connection path.
 */
class WebrtcIce {
public:
    enum class CandidateType {
        HOST,
        SRFLX, // Server Reflexive (STUN)
        PRFLX, // Peer Reflexive
        RELAY  // TURN
    };

    struct Candidate {
        std::string foundation;
        int component; // 1 for RTP, 2 for RTCP
        std::string transport; // UDP, TCP
        uint32_t priority;
        std::string ip;
        int port;
        CandidateType type;
        std::string related_address;
        int related_port;
    };

    WebrtcIce();
    ~WebrtcIce();

    void add_local_candidate(const Candidate& candidate);
    void add_remote_candidate(const Candidate& candidate);
    
    struct Pairing {
        Candidate local;
        Candidate remote;
        uint64_t priority;
        bool valid;
    };

    std::vector<Pairing> compute_check_lists();

private:
    std::vector<Candidate> local_candidates_;
    std::vector<Candidate> remote_candidates_;
};

} // namespace nit::osnova::media
