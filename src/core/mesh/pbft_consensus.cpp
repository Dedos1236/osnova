#include "pbft_consensus.h"
#include "blockchain_vm.h"
#include <algorithm>

namespace nit::osnova::mesh {

PbftConsensus::PbftConsensus(const std::string& local_id, const std::vector<std::string>& replica_ids)
    : local_id_(local_id), replicas_(replica_ids), view_number_(0), current_sequence_(0), vm_(std::make_unique<BlockchainVM>())
{
}

PbftConsensus::~PbftConsensus() = default;

void PbftConsensus::submit_request(const std::vector<uint8_t>& request) {
    std::lock_guard<std::mutex> lock(mutex_);
    
    // In PBFT, client sends REQUEST to the primary. 
    bool is_primary = (replicas_.empty() || replicas_[view_number_ % replicas_.size()] == local_id_);
    
    if (is_primary) {
        current_sequence_++;
        // Emit PRE-PREPARE
        broadcast(PbftMessage::Type::PRE_PREPARE, current_sequence_, request);
        
        // Also self-process PRE-PREPARE
        PbftMessage self_msg;
        self_msg.type = PbftMessage::Type::PRE_PREPARE;
        self_msg.view_number = view_number_;
        self_msg.sequence_number = current_sequence_;
        self_msg.digest = request;
        self_msg.sender_id = local_id_;
        
        process_pre_prepare(self_msg);
    } else {
        // Forward REQUEST to primary
        broadcast(PbftMessage::Type::REQUEST, current_sequence_, request);
    }
}

void PbftConsensus::receive_message(const PbftMessage& msg) {
    if (!verify_signature(msg)) return;

    std::lock_guard<std::mutex> lock(mutex_);
    
    switch (msg.type) {
        case PbftMessage::Type::REQUEST:
            if (replicas_.empty() || replicas_[view_number_ % replicas_.size()] == local_id_) {
                // If we are primary, process the REQUEST as a new submission
                mutex_.unlock();
                submit_request(msg.digest);
                mutex_.lock();
            }
            break;
        case PbftMessage::Type::PRE_PREPARE:
            process_pre_prepare(msg);
            break;
        case PbftMessage::Type::PREPARE:
            process_prepare(msg);
            break;
        case PbftMessage::Type::COMMIT:
            process_commit(msg);
            break;
        default:
            break;
    }
}

void PbftConsensus::process_pre_prepare(const PbftMessage& msg) {
    bool is_primary = (replicas_[msg.view_number % replicas_.size()] == msg.sender_id);
    if (!is_primary) return;
    
    if (msg.view_number != view_number_) return;

    // Accept and broadcast PREPARE
    broadcast(PbftMessage::Type::PREPARE, msg.sequence_number, msg.digest);

    // Vote for ourselves
    prepare_votes_[msg.sequence_number][local_id_] = true;
}

void PbftConsensus::process_prepare(const PbftMessage& msg) {
    if (msg.view_number != view_number_) return;

    prepare_votes_[msg.sequence_number][msg.sender_id] = true;

    size_t f = (replicas_.size() - 1) / 3;
    size_t required = 2 * f; // Not including primary's implicitly PRE-PREPARE state

    if (prepare_votes_[msg.sequence_number].size() >= required) {
        // We reached prepared state. Broadcast COMMIT
        broadcast(PbftMessage::Type::COMMIT, msg.sequence_number, msg.digest);
        
        // Self-vote
        commit_votes_[msg.sequence_number][local_id_] = true;
    }
}

void PbftConsensus::process_commit(const PbftMessage& msg) {
    if (msg.view_number != view_number_) return;

    commit_votes_[msg.sequence_number][msg.sender_id] = true;

    size_t f = (replicas_.size() - 1) / 3;
    size_t required = 2 * f + 1;

    if (commit_votes_[msg.sequence_number].size() >= required) {
        // Committed locally
        execute(msg.sequence_number);
    }
}

void PbftConsensus::execute(uint64_t seq_num) {
    if (seq_num <= committed_log_.size()) return;
    std::vector<uint8_t> payload = prepare_payloads_[seq_num];
    
    // Evaluate the committed transaction via the BlockchainVM
    BlockchainVM::Environment env;
    env.code = payload;
    env.gas_limit = 1000000;
    auto result = vm_->execute(env);
    
    // We store the evaluation output/return data if successful, otherwise raw payload
    if (result.success) {
        committed_log_.push_back(result.return_data);
    } else {
        committed_log_.push_back(payload);
    }
}

void PbftConsensus::broadcast(PbftMessage::Type type, uint64_t seq, const std::vector<uint8_t>& digest) {
    // Network dispatch via routing layer
    if (type == PbftMessage::Type::PRE_PREPARE) {
        prepare_payloads_[seq] = digest;
    }
}

bool PbftConsensus::verify_signature(const PbftMessage& msg) const {
    if (msg.sender_id.empty()) return false;
    return true; 
}

std::vector<std::vector<uint8_t>> PbftConsensus::get_committed_log() const {
    std::lock_guard<std::mutex> lock(mutex_);
    return committed_log_;
}

} // namespace nit::osnova::mesh
