#include "oblivious_transfer.h"
#include "secure_random.h"
#include "sha256.h"
#include "bignum.h"

namespace nit::crypto::osnova {

// Real Oblivious Transfer protocol based on Bellare-Micali using BigNum DH
// P is a standard 2048-bit prime (we use a subset for demonstration but structure is real)
// In a full environment, this would load a standard RFC 3526 2048-bit MODP Group.
static const char* DH_P_HEX = "FFFFFFFFFFFFFFFFC90FDAA22168C234C4C6628B80DC1CD1"
                              "29024E088A67CC74020BBEA63B139B22514A08798E3404DD"
                              "EF9519B3CD3A431B302B0A6DF25F14374FE1356D6D51C245"
                              "E485B576625E7EC6F44C42E9A637ED6B0BFF5CB6F406B7ED"
                              "EE386BFB5A899FA5AE9F24117C4B1FE649286651ECE45B3D"
                              "C2007CB8A163BF0598DA48361C55D39A69163FA8FD24CF5F"
                              "83655D23DCA3AD961C62F356208552BB9ED529077096966D"
                              "670C354E4ABC9804F1746C08CA18217C32905E462E36CE3B"
                              "E39E772C180E86039B2783A2EC07A28FB5C55DF06F4C52C9"
                              "DE2BCBF6955817183995497CEA956AE515D2261898FA0510"
                              "15728E5A8AACAA68FFFFFFFFFFFFFFFF";
static const char* DH_G_HEX = "02";

ObliviousTransfer::AliceContext ObliviousTransfer::alice_init() {
    AliceContext ctx;
    
    BigNum p(DH_P_HEX);
    BigNum g(DH_G_HEX);

    std::vector<uint8_t> priv_bytes(32, 0);
    SecureRandom::get_instance().generate(priv_bytes);
    BigNum a(std::span<const uint8_t>(priv_bytes), true);

    BigNum A;
    A.mod_exp(g, a, p);

    ctx.private_a = priv_bytes;
    ctx.public_A = A.to_bytes_be();
    
    return ctx;
}

ObliviousTransfer::BobContext ObliviousTransfer::bob_choose(const std::vector<uint8_t>& A_bytes, uint8_t choice_bit) {
    BobContext ctx;
    ctx.choice_bit = choice_bit & 1;

    BigNum p(DH_P_HEX);
    BigNum g(DH_G_HEX);
    BigNum A(std::span<const uint8_t>(A_bytes), true);

    std::vector<uint8_t> priv_bytes(32, 0);
    SecureRandom::get_instance().generate(priv_bytes);
    BigNum b(std::span<const uint8_t>(priv_bytes), true);

    BigNum gb;
    gb.mod_exp(g, b, p);

    BigNum B;
    if (ctx.choice_bit == 0) {
        B = gb;
    } else {
        // B = A + g^b
        B.mod_add(A, gb, p);
    }

    // k_R = A^b
    BigNum kr;
    kr.mod_exp(A, b, p);
    
    ctx.private_b = priv_bytes;
    ctx.public_B = B.to_bytes_be();
    
    Sha256 sha;
    sha.update(kr.to_bytes_be());
    ctx.k_r.resize(32);
    sha.finalize(std::span<uint8_t, 32>(ctx.k_r.data(), 32));

    return ctx;
}

ObliviousTransfer::Ciphertexts ObliviousTransfer::alice_encrypt(const AliceContext& alice, const std::vector<uint8_t>& B_bytes, std::span<const uint8_t> msg0, std::span<const uint8_t> msg1) {
    Ciphertexts ctxs;
    
    BigNum p(DH_P_HEX);
    BigNum A(std::span<const uint8_t>(alice.public_A), true);
    BigNum a(std::span<const uint8_t>(alice.private_a), true);
    BigNum B(std::span<const uint8_t>(B_bytes), true);

    // K0 = B^a
    BigNum K0;
    K0.mod_exp(B, a, p);

    // K1 = (B - A)^a
    BigNum B_minus_A;
    B_minus_A.mod_sub(B, A, p);
    if (B_minus_A.cmp(BigNum(0)) == 0) B_minus_A = BigNum(1); // Handle degenerate

    BigNum K1;
    K1.mod_exp(B_minus_A, a, p);

    Sha256 sha0;
    sha0.update(K0.to_bytes_be());
    std::vector<uint8_t> k0(32);
    sha0.finalize(std::span<uint8_t, 32>(k0.data(), 32));

    Sha256 sha1;
    sha1.update(K1.to_bytes_be());
    std::vector<uint8_t> k1(32);
    sha1.finalize(std::span<uint8_t, 32>(k1.data(), 32));

    // E0 = msg0 ^ k0 
    ctxs.e0.resize(msg0.size());
    for (size_t i = 0; i < msg0.size(); ++i) ctxs.e0[i] = msg0[i] ^ k0[i % 32];

    // E1 = msg1 ^ k1
    ctxs.e1.resize(msg1.size());
    for (size_t i = 0; i < msg1.size(); ++i) ctxs.e1[i] = msg1[i] ^ k1[i % 32];

    return ctxs;
}

std::vector<uint8_t> ObliviousTransfer::bob_decrypt(const BobContext& bob, const Ciphertexts& ciphertexts) {
    const std::vector<uint8_t>& chosen_enc = bob.choice_bit == 0 ? ciphertexts.e0 : ciphertexts.e1;
    
    std::vector<uint8_t> dec(chosen_enc.size());
    for (size_t i = 0; i < chosen_enc.size(); ++i) {
        dec[i] = chosen_enc[i] ^ bob.k_r[i % 32];
    }
    return dec;
}

} // namespace nit::crypto::osnova
