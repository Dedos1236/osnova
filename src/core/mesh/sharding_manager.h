#pragma once

#include <vector>
#include <map>
#include <mutex>
#include "pbft_consensus.h"
#include "../crypto/ff_bn254.h"

namespace nit::osnova::mesh {

using ShardId = uint32_t;

struct CrossShardTransaction {
    ShardId source;
    ShardId destination;
    std::vector<uint8_t> payload;
    std::vector<uint8_t> zk_proof;
};

/**
 * @brief OSNOVA Sharding Engine.
 * Implements ZK-Rollup cross-shard validation and Data Availability state resolution 
 * using Finite Fields and Reed-Solomon Erasure Coding over GF(2^8).
 */
class ShardingManager {
public:
    explicit ShardingManager(ShardId id);
    
    // Broadcast cross-shard tx securely
    void dispatch_cross_shard(const CrossShardTransaction& ctx);
    
    // Validate an incoming ZK cross-shard tx computationally 
    bool validate_cross_shard(const CrossShardTransaction& ctx);
    
    // Integrate data availability sample utilizing Galois Field recovery
    void push_da_sample(uint64_t block_seq, int chunk_idx, const std::vector<uint8_t>& chunk);

private:
    ShardId my_shard_;
    std::mutex mtx_;
    std::map<uint64_t, std::vector<std::vector<uint8_t>>> da_buffer_;
};

} // namespace nit::osnova::mesh
