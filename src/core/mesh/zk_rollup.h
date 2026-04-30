#pragma once

#include "sharding_manager.h"
#include "../crypto/plonk_prover.h"
#include "../crypto/plonk_verifier.h"

namespace nit::osnova::mesh {

class ZkRollupManager {
public:
    ZkRollupManager(uint32_t shard_id);

    void process_transactions(const std::vector<std::vector<uint8_t>>& txs);
    CrossShardTransaction finalize_batch();
    
private:
    uint32_t my_shard_;
    std::vector<std::vector<uint8_t>> mempool;
    
    nit::crypto::osnova::KZG10Commitment::SRS srs_;
    nit::crypto::osnova::PlonkProver::ProvingKey pk_;
    nit::crypto::osnova::PlonkCircuit circuit_;
};

} // namespace nit::osnova::mesh
