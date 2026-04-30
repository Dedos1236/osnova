#pragma once

#include <cstdint>
#include <vector>
#include <span>
#include <unordered_map>
#include <mutex>
#include <string>

namespace nit::osnova::mesh {

struct PbftMessage {
    enum class Type {
        REQUEST,
        PRE_PREPARE,
        PREPARE,
        COMMIT,
        REPLY
    };

    Type type;
    uint64_t view_number;
    uint64_t sequence_number;
    std::vector<uint8_t> digest; // Hash of the client request
    std::string sender_id;
    std::vector<uint8_t> signature;
};

class BlockchainVM;

/**
 * @brief Practical Byzantine Fault Tolerance (PBFT) consensus protocol.
 * Secures OSNOVA ledger blocks against arbitrarily malicious nodes (up to < 33% faulty).
 */
class PbftConsensus {
public:
    explicit PbftConsensus(const std::string& local_id, const std::vector<std::string>& replica_ids);
    ~PbftConsensus();

    /**
     * @brief Client submits a new request to be committed to the log.
     */
    void submit_request(const std::vector<uint8_t>& Request);

    /**
     * @brief Handle incoming PBFT protocol message from network.
     */
    void receive_message(const PbftMessage& msg);

    /**
     * @brief Extract committed operations for application logic processing.
     */
    std::vector<std::vector<uint8_t>> get_committed_log() const;

private:
    std::string local_id_;
    std::vector<std::string> replicas_;
    uint64_t view_number_;
    uint64_t current_sequence_;

    // Operation logs
    std::vector<std::vector<uint8_t>> committed_log_;
    
    // Tracking message counts
    // sequence_number -> sender_id -> msg_hash
    std::unordered_map<uint64_t, std::unordered_map<std::string, bool>> prepare_votes_;
    std::unordered_map<uint64_t, std::unordered_map<std::string, bool>> commit_votes_;
    std::unordered_map<uint64_t, std::vector<uint8_t>> prepare_payloads_;
    
    std::unique_ptr<BlockchainVM> vm_;
    
    mutable std::mutex mutex_;

    void process_pre_prepare(const PbftMessage& msg);
    void process_prepare(const PbftMessage& msg);
    void process_commit(const PbftMessage& msg);
    void execute(uint64_t seq_num);

    void broadcast(PbftMessage::Type type, uint64_t seq, const std::vector<uint8_t>& digest);
    bool verify_signature(const PbftMessage& msg) const;
};

} // namespace nit::osnova::mesh
