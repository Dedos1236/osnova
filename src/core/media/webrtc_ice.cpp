#include "webrtc_ice.h"
#include <algorithm>

namespace nit::osnova::media {

WebrtcIce::WebrtcIce() = default;
WebrtcIce::~WebrtcIce() = default;

void WebrtcIce::add_local_candidate(const Candidate& candidate) {
    local_candidates_.push_back(candidate);
}

void WebrtcIce::add_remote_candidate(const Candidate& candidate) {
    remote_candidates_.push_back(candidate);
}

std::vector<WebrtcIce::Pairing> WebrtcIce::compute_check_lists() {
    std::vector<Pairing> pairings;

    for (const auto& local : local_candidates_) {
        for (const auto& remote : remote_candidates_) {
            if (local.component == remote.component && local.transport == remote.transport) {
                Pairing p;
                p.local = local;
                p.remote = remote;
                p.valid = false;
                
                // Priority = (2^32)*MIN(G,D) + 2*MAX(G,D) + (G>D?1:0)
                uint32_t G = local.priority; // Assume we are controlling
                uint32_t D = remote.priority;
                
                uint64_t min_pri = std::min(G, D);
                uint64_t max_pri = std::max(G, D);
                
                p.priority = (min_pri << 32) + (2 * max_pri) + (G > D ? 1 : 0);
                
                pairings.push_back(p);
            }
        }
    }

    std::sort(pairings.begin(), pairings.end(), [](const Pairing& a, const Pairing& b) {
        return a.priority > b.priority; // Descending
    });

    return pairings;
}

} // namespace nit::osnova::media
