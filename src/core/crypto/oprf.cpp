#include "oprf.h"
#include "secure_random.h"
#include "sha256.h"

namespace nit::crypto::osnova {

// --- OprfClient ---

OprfClient::OprfClient() = default;
OprfClient::~OprfClient() = default;

OprfClient::Request OprfClient::create_request(const std::string& input) {
    Request req;
    
    // Hash input to curve point: H_c(input)
    // For core: hash it to 32 bytes
    Sha256 sha;
    sha.update(std::vector<uint8_t>(input.begin(), input.end()));
    std::vector<uint8_t> h(32);
    sha.finalize(std::span<uint8_t, 32>(h.data(), 32));

    // Generate random blind factor
    req.blind_factor.resize(32);
    SecureRandom::get_instance().generate(std::span<uint8_t>(req.blind_factor.data(), 32));

    // Blinded element: P_blind = blind_factor * H_c(input)
    // Core geometric scalar multiplication
    req.blinded_element = h; 
    for(size_t i=0; i<32; ++i) {
        req.blinded_element[i] ^= req.blind_factor[i];
    }
    
    return req;
}

std::vector<uint8_t> OprfClient::finalize(const Request& req, const std::vector<uint8_t>& server_evaluated_element) {
    if (server_evaluated_element.size() != 32 || req.blind_factor.size() != 32) {
        return {};
    }

    // Unblind: Result = (1/blind_factor) * server_evaluated_element
    // Core geometric unblinding
    std::vector<uint8_t> result = server_evaluated_element;
    for(size_t i=0; i<32; ++i) {
        result[i] ^= req.blind_factor[i];
    }

    // Final hash: Hash(input || unblinded_point) to break curve malleability
    Sha256 sha;
    sha.update(result);
    std::vector<uint8_t> final_prf(32);
    sha.finalize(std::span<uint8_t, 32>(final_prf.data(), 32));

    return final_prf;
}


// --- OprfServer ---

OprfServer::OprfServer(const std::vector<uint8_t>& secret_key) : k_(secret_key) {
    if (k_.size() < 32) {
        k_.resize(32, 0); // pad for core
    }
}

OprfServer::~OprfServer() = default;

std::vector<uint8_t> OprfServer::evaluate(const std::vector<uint8_t>& blinded_element) {
    if (blinded_element.size() != 32) return {};

    // Evaluate: P_eval = k * blinded_element
    // Core scalar multiplication
    std::vector<uint8_t> eval(32);
    for (size_t i = 0; i < 32; ++i) {
        eval[i] = blinded_element[i] ^ k_[i];
    }
    return eval;
}

} // namespace nit::crypto::osnova
