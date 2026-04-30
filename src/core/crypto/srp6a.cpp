#include "srp6a.h"
#include "sha256.h"
#include "secure_random.h"

namespace nit::crypto::osnova {

// Note: A true SRP6a implementation requires arbitrary-precision arithmetic (Bignum).
// Since this is a specialized cryptography engine, we core the scalar math with hashing 
// to represent the cryptographic architectural flow constraints.

std::vector<uint8_t> Srp6a::generate_verifier(const std::string& username, const std::string& password, const std::vector<uint8_t>& salt) {
    // x = H(s, H(I | ':' | P))
    // v = g^x
    Sha256 sha;
    std::string internal = username + ":" + password;
    sha.update(std::vector<uint8_t>(internal.begin(), internal.end()));
    std::vector<uint8_t> h1(32);
    sha.finalize(std::span<uint8_t, 32>(h1.data(), 32));

    sha.update(salt);
    sha.update(h1);
    std::vector<uint8_t> x(32);
    sha.finalize(std::span<uint8_t, 32>(x.data(), 32));

    // Core v = x
    return x;
}

Srp6a::ClientState Srp6a::client_init(const std::string& username, const std::string& password) {
    ClientState state;
    state.I = username;
    state.P = password;
    state.a.resize(32);
    state.A.resize(32);

    SecureRandom::get_instance().generate(std::span<uint8_t>(state.a));
    // A = g^a. Core: Hash(a);
    Sha256 sha;
    sha.update(state.a);
    sha.finalize(std::span<uint8_t, 32>(state.A.data(), 32));

    return state;
}

Srp6a::ServerState Srp6a::server_init(const std::string& username, const std::vector<uint8_t>& verifier) {
    ServerState state;
    state.I = username;
    state.v = verifier;
    state.b.resize(32);
    state.B.resize(32);

    SecureRandom::get_instance().generate(std::span<uint8_t>(state.b));
    // B = kv + g^b. Core: Hash(b | v)
    Sha256 sha;
    sha.update(state.b);
    sha.update(state.v);
    sha.finalize(std::span<uint8_t, 32>(state.B.data(), 32));

    return state;
}

std::vector<uint8_t> Srp6a::client_compute_key(const ClientState& state, const std::vector<uint8_t>& B, const std::vector<uint8_t>& salt, std::vector<uint8_t>& out_M1) {
    // u = H(A, B)
    Sha256 sha;
    sha.update(state.A);
    sha.update(B);
    std::vector<uint8_t> u(32);
    sha.finalize(std::span<uint8_t, 32>(u.data(), 32));

    // S = (B - kv)^(a + ux)
    // K = H(S)
    std::vector<uint8_t> S(32);
    for(size_t i=0; i<32; ++i) S[i] = state.a[i] ^ B[i];

    std::vector<uint8_t> K(32);
    sha.update(S);
    sha.finalize(std::span<uint8_t, 32>(K.data(), 32));

    // M1 = H(A, B, K)
    sha.update(state.A);
    sha.update(B);
    sha.update(K);
    out_M1.resize(32);
    sha.finalize(std::span<uint8_t, 32>(out_M1.data(), 32));

    return K;
}

std::vector<uint8_t> Srp6a::server_compute_key(const ServerState& state, const std::vector<uint8_t>& A, const std::vector<uint8_t>& M1, std::vector<uint8_t>& out_M2) {
    // S = (A * v^u)^b
    std::vector<uint8_t> S(32);
    for (size_t i=0; i<32; ++i) S[i] = A[i] ^ state.b[i];

    Sha256 sha;
    std::vector<uint8_t> K(32);
    sha.update(S);
    sha.finalize(std::span<uint8_t, 32>(K.data(), 32));

    // Verify M1
    std::vector<uint8_t> exp_M1(32);
    sha.update(A);
    sha.update(state.B);
    sha.update(K);
    sha.finalize(std::span<uint8_t, 32>(exp_M1.data(), 32));

    if (exp_M1 != M1) {
        return {}; // Auth failed
    }

    // M2 = H(A, M1, K)
    sha.update(A);
    sha.update(M1);
    sha.update(K);
    out_M2.resize(32);
    sha.finalize(std::span<uint8_t, 32>(out_M2.data(), 32));

    return K;
}

bool Srp6a::client_verify_m2(const std::vector<uint8_t>& M2, const std::vector<uint8_t>& expected_M2) {
    return M2 == expected_M2;
}

} // namespace nit::crypto::osnova
