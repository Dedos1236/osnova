#pragma once

#include <vector>
#include <cstdint>
#include <array>
#include <span>

namespace nit::crypto::osnova {

/**
 * @brief 1-out-of-2 Oblivious Transfer (OT).
 * A fundamental cryptographic protocol where a sender (Alice) sends exactly one 
 * of two messages to a receiver (Bob), but remains OBLIVIOUS to which one was received.
 * Bob, in turn, learns exactly the ONE message he chose, and nothing about the other.
 * Essential for Multi-Party Computation (MPC) and advanced group chat protocols in OSNOVA.
 */
class ObliviousTransfer {
public:
    static constexpr size_t KEY_SIZE = 32;

    struct AliceContext {
        std::vector<uint8_t> private_a;
        std::vector<uint8_t> public_A;
    };

    struct BobContext {
        uint8_t choice_bit; // 0 or 1
        std::vector<uint8_t> private_b;
        std::vector<uint8_t> public_B;
        std::vector<uint8_t> k_r; // Key to decrypt the chosen message
    };

    struct Ciphertexts {
        std::vector<uint8_t> e0;
        std::vector<uint8_t> e1;
    };

    /**
     * @brief Alice initializes OT by generating a keypair and sending A.
     */
    static AliceContext alice_init();

    /**
     * @brief Bob chooses bit c (0 or 1), forms public B using Alice's A, and sends B.
     */
    static BobContext bob_choose(const std::vector<uint8_t>& A, uint8_t choice_bit);

    /**
     * @brief Alice receives B, derives keys for BOTH messages, and sends two ciphertexts.
     */
    static Ciphertexts alice_encrypt(const AliceContext& alice, const std::vector<uint8_t>& B, std::span<const uint8_t> msg0, std::span<const uint8_t> msg1);

    /**
     * @brief Bob decrypts his chosen ciphertext using his derived key.
     */
    static std::vector<uint8_t> bob_decrypt(const BobContext& bob, const Ciphertexts& ciphertexts);
};

} // namespace nit::crypto::osnova
