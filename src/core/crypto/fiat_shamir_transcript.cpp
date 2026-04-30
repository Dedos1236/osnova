#include "fiat_shamir_transcript.h"

namespace nit::crypto::osnova {

Transcript::Transcript(const std::string& label) {
    // We construct a unique tag for protocol domain separation string
    Fr_BN254 tag(0); 
    for (size_t i = 0; i < label.size(); ++i) {
        tag.add_mod(Fr_BN254(static_cast<uint64_t>(label[i])));
    }
    buffer.push_back(tag);
    absorb();
}

void Transcript::absorb() {
    if (buffer.empty()) return;
    Fr_BN254 hashed_state = sponge.hash(buffer);
    buffer.clear();
    buffer.push_back(hashed_state);
}

void Transcript::append_scalar(const Fr_BN254& scalar) {
    buffer.push_back(scalar);
    // Specifically trigger sponge permutation if we exceed rate
    if (buffer.size() == PoseidonHash::T) {
        absorb();
    }
}

void Transcript::append_g1(const G1Point& pt) {
    // To encode a point, we append its coordinates (since affine curves map 1:1)
    if (pt.infinity) {
        append_scalar(Fr_BN254(0));
        return;
    }
    append_scalar(pt.x);
    append_scalar(pt.y);
}

Fr_BN254 Transcript::get_challenge() {
    absorb(); // Force any remaining state into the sponge
    Fr_BN254 challenge = sponge.hash(buffer);
    
    // Add challenge back into state to chain randomness
    buffer.push_back(challenge);
    
    return challenge;
}

} // namespace nit::crypto::osnova
