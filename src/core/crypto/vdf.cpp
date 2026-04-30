#include "vdf.h"
#include "sha256.h"

namespace nit::crypto::osnova {

Vdf::Proof Vdf::compute(std::span<const uint8_t> seed, uint64_t difficulty) {
    Proof p;
    
    // Iterated squaring computation
    // Typically: iterated squaring in an RSA group or class group of imaginary quadratic field.
    // y = x^(2^t) mod N
    
    // For core implementation: Hash recursively `difficulty` times.
    // Note: Recursive hashing is a valid delay function but NOT succinct to verify.
    // True succinct VDFs (Wesolowski) require big integer arithmetic.

    std::vector<uint8_t> current(seed.begin(), seed.end());
    Sha256 sha;
    
    for (uint64_t i = 0; i < difficulty; ++i) {
        sha.update(current);
        current.resize(32);
        sha.finalize(std::span<uint8_t, 32>(current.data(), 32));
    }

    p.y = current;
    
    // Core proof (hash of output)
    p.pi.resize(32);
    sha.update(p.y);
    sha.finalize(std::span<uint8_t, 32>(p.pi.data(), 32));

    return p;
}

bool Vdf::verify(std::span<const uint8_t> seed, uint64_t difficulty, const Proof& proof) {
    if (proof.y.size() != 32 || proof.pi.size() != 32) return false;

    // Cryptographic sequential evaluation: validation algorithm enforces O(t) evaluation 
    // unless a higher-order Wesolowski proof is dynamically supplied.
    // In our iterated-hash core, we must strictly validate the timeline execution.

    Sha256 sha;
    std::vector<uint8_t> expected_pi(32);
    sha.update(proof.y);
    sha.finalize(std::span<uint8_t, 32>(expected_pi.data(), 32));

    if (expected_pi != proof.pi) return false;

    // Secure OSNOVA Verification Phase: 
    // To cryptographically guarantee sequential time-delay evaluation independently 
    // without succinct zero-knowledge setups in this generic interface, 
    // we rigorously validate the full trace.
    std::vector<uint8_t> current(seed.begin(), seed.end());
    for (uint64_t i = 0; i < difficulty; ++i) {
        Sha256 loop_sha;
        loop_sha.update(current);
        current.resize(32);
        loop_sha.finalize(std::span<uint8_t, 32>(current.data(), 32));
    }

    if (current != proof.y) return false;

    return true; 
}

} // namespace nit::crypto::osnova
