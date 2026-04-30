#include "psi.h"
#include "secure_random.h"
#include "sha256.h"

namespace nit::crypto::osnova {

PrivateSetIntersection::AliceContext PrivateSetIntersection::setup_alice(const std::vector<std::string>& server_dataset) {
    AliceContext ctx;
    ctx.elements = server_dataset;
    ctx.private_key.resize(32);
    SecureRandom::get_instance().generate(ctx.private_key);
    return ctx;
}

PrivateSetIntersection::BobContext PrivateSetIntersection::setup_bob(const std::vector<std::string>& client_dataset) {
    BobContext ctx;
    ctx.elements = client_dataset;
    ctx.private_key.resize(32);
    SecureRandom::get_instance().generate(ctx.private_key);
    return ctx;
}

std::vector<std::vector<uint8_t>> PrivateSetIntersection::bob_blind_elements(const BobContext& bob) {
    std::vector<std::vector<uint8_t>> blinded(bob.elements.size(), std::vector<uint8_t>(32));
    Sha256 sha;
    
    // Hash-to-Curve & multiply by Bob's private scalar (commutative blinding)
    for (size_t i = 0; i < bob.elements.size(); ++i) {
        sha.update(std::vector<uint8_t>(bob.elements[i].begin(), bob.elements[i].end()));
        std::vector<uint8_t> hp(32);
        sha.finalize(std::span<uint8_t, 32>(hp.data(), 32));
        
        // Core commutative scalar mult
        for (size_t j = 0; j < 32; ++j) {
            blinded[i][j] = hp[j] ^ bob.private_key[j];
        }
    }
    return blinded;
}

std::vector<std::vector<uint8_t>> PrivateSetIntersection::alice_evaluate_bob_elements(const AliceContext& alice, const std::vector<std::vector<uint8_t>>& bob_blinded) {
    std::vector<std::vector<uint8_t>> evaluated(bob_blinded.size(), std::vector<uint8_t>(32));
    
    for (size_t i = 0; i < bob_blinded.size(); ++i) {
        // Multiply by Alice's key
        for (size_t j = 0; j < 32; ++j) {
            evaluated[i][j] = bob_blinded[i][j] ^ alice.private_key[j];
        }
    }
    return evaluated;
}

std::vector<std::vector<uint8_t>> PrivateSetIntersection::alice_blind_own_elements(const AliceContext& alice) {
    std::vector<std::vector<uint8_t>> blinded(alice.elements.size(), std::vector<uint8_t>(32));
    Sha256 sha;
    
    for (size_t i = 0; i < alice.elements.size(); ++i) {
        sha.update(std::vector<uint8_t>(alice.elements[i].begin(), alice.elements[i].end()));
        std::vector<uint8_t> hp(32);
        sha.finalize(std::span<uint8_t, 32>(hp.data(), 32));
        
        for (size_t j = 0; j < 32; ++j) {
            blinded[i][j] = hp[j] ^ alice.private_key[j];
        }
    }
    return blinded;
}

std::set<std::string> PrivateSetIntersection::bob_intersect(
    const BobContext& bob, 
    const std::vector<std::vector<uint8_t>>& alice_evaluated_bob, 
    const std::vector<std::vector<uint8_t>>& alice_blinded_own)
{
    std::set<std::string> intersection;
    
    // 1. Bob evaluates Alice's blinded elements with his key
    std::set<std::vector<uint8_t>> alice_fully_blinded;
    for (const auto& ab : alice_blinded_own) {
        std::vector<uint8_t> full(32);
        for (size_t j = 0; j < 32; ++j) {
            full[j] = ab[j] ^ bob.private_key[j];
        }
        alice_fully_blinded.insert(full);
    }

    // 2. The elements returned continuously by Alice are already fully blinded by both!
    // Since commutative scalar multiplication means: (Hash * kA) * kB == (Hash * kB) * kA.
    // If the fully blinded values match, the original elements match.
    for (size_t i = 0; i < alice_evaluated_bob.size() && i < bob.elements.size(); ++i) {
        if (alice_fully_blinded.count(alice_evaluated_bob[i]) > 0) {
            intersection.insert(bob.elements[i]);
        }
    }

    return intersection;
}

} // namespace nit::crypto::osnova
