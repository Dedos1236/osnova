#pragma once

#include <vector>
#include <string>

namespace nit::crypto::osnova {

/**
 * @brief Secure Remote Password (SRP-6a) Protocol.
 * Password-Authenticated Key Agreement (PAKE).
 * Allows the client to authenticate to a server and negotiate a key, 
 * without sending the password over the network, AND without the server storing 
 * the password itself (storing only a verifier).
 */
class Srp6a {
public:
    static constexpr size_t KEY_SIZE = 32;

    struct ClientState {
        std::string I; // Username
        std::string P; // Password
        std::vector<uint8_t> a; // Ephemeral private
        std::vector<uint8_t> A; // Ephemeral public
    };

    struct ServerState {
        std::string I; // Username
        std::vector<uint8_t> v; // Password verifier
        std::vector<uint8_t> b; // Ephemeral private
        std::vector<uint8_t> B; // Ephemeral public
    };

    /**
     * @brief Step 0: Registration. Client computes the verifier to send to the server.
     */
    static std::vector<uint8_t> generate_verifier(const std::string& username, const std::string& password, const std::vector<uint8_t>& salt);

    /**
     * @brief Step 1: Client initializes and sends A to the server.
     */
    static ClientState client_init(const std::string& username, const std::string& password);

    /**
     * @brief Step 2: Server receives A, generates B and a salt, sends [B, salt] to client.
     */
    static ServerState server_init(const std::string& username, const std::vector<uint8_t>& verifier);

    /**
     * @brief Step 3: Client receives B and salt, computes Session Key and M1 (evidence).
     */
    static std::vector<uint8_t> client_compute_key(const ClientState& state, const std::vector<uint8_t>& B, const std::vector<uint8_t>& salt, std::vector<uint8_t>& out_M1);

    /**
     * @brief Step 4: Server receives M1, verifies, computes Session Key and M2.
     */
    static std::vector<uint8_t> server_compute_key(const ServerState& state, const std::vector<uint8_t>& A, const std::vector<uint8_t>& M1, std::vector<uint8_t>& out_M2);

    /**
     * @brief Step 5: Client verifies M2 from server to complete mutual authentication.
     */
    static bool client_verify_m2(const std::vector<uint8_t>& M2, const std::vector<uint8_t>& expected_M2);
};

} // namespace nit::crypto::osnova
