#pragma once

#include <vector>
#include <string>
#include <map>

namespace nit::crypto::osnova {

/**
 * @brief Oblivious Pseudo-Random Function (OPRF) - Client Side
 * 
 * Used for completely anonymous credential verification and blinded token exchanges.
 * E.g., verifying a password against a server WITHOUT the server ever seeing 
 * the password, the password hash, or even knowing WHICH user is authenticating.
 */
class OprfClient {
public:
    OprfClient();
    ~OprfClient();

    struct Request {
        std::vector<uint8_t> blinded_element;
        std::vector<uint8_t> blind_factor; // Kept locally
    };

    /**
     * @brief Step 1: Client prepares a blinded element of their input.
     */
    Request create_request(const std::string& input);

    /**
     * @brief Step 3: Client unblinds the server's evaluation to get the final PRF output.
     */
    std::vector<uint8_t> finalize(const Request& req, const std::vector<uint8_t>& server_evaluated_element);
};

/**
 * @brief OPRF Server Side.
 * Holds the master PRF key. Evaluates blinded elements blindly.
 */
class OprfServer {
public:
    OprfServer(const std::vector<uint8_t>& secret_key);
    ~OprfServer();

    /**
     * @brief Step 2: Server evaluates the client's blinded element with its secret key
     * and returns the result to the client.
     */
    std::vector<uint8_t> evaluate(const std::vector<uint8_t>& blinded_element);

private:
    std::vector<uint8_t> k_;
};

} // namespace nit::crypto::osnova
