#pragma once

#include <vector>
#include <string>
#include <set>
#include <span>

namespace nit::crypto::osnova {

/**
 * @brief Private Set Intersection (PSI).
 * Allows two parties (Alice and Bob) to find the intersection of their 
 * data sets (e.g., Contact Lists) without either party learning any 
 * elements of the other party's set that are NOT in the intersection.
 */
class PrivateSetIntersection {
public:
    struct AliceContext {
        std::vector<uint8_t> private_key;
        std::vector<std::string> elements;
    };

    struct BobContext {
        std::vector<uint8_t> private_key;
        std::vector<std::string> elements;
    };

    /**
     * @brief Setup for Alice (Server/Contact DB).
     */
    static AliceContext setup_alice(const std::vector<std::string>& server_dataset);

    /**
     * @brief Setup for Bob (Client). 
     * Bob blinds his contact list to send to Alice.
     */
    static BobContext setup_bob(const std::vector<std::string>& client_dataset);
    static std::vector<std::vector<uint8_t>> bob_blind_elements(const BobContext& bob);

    /**
     * @brief Alice processes Bob's blinded elements and sends them back.
     * She also sends her own dataset, blinded by her key.
     */
    static std::vector<std::vector<uint8_t>> alice_evaluate_bob_elements(const AliceContext& alice, const std::vector<std::vector<uint8_t>>& bob_blinded);
    static std::vector<std::vector<uint8_t>> alice_blind_own_elements(const AliceContext& alice);

    /**
     * @brief Bob fully decrypts the intersection.
     */
    static std::set<std::string> bob_intersect(
        const BobContext& bob, 
        const std::vector<std::vector<uint8_t>>& alice_evaluated_bob, 
        const std::vector<std::vector<uint8_t>>& alice_blinded_own);
};

} // namespace nit::crypto::osnova
