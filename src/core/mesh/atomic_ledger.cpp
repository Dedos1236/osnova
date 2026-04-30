#include "atomic_ledger.h"
#include <fstream>
#include <map>
#include <iostream>

namespace nit::mesh {

struct AtomicLedger::Impl {
    std::mutex mtx;
    std::filesystem::path db_path;
    
    // In-memory index of MsgID -> offset
    std::map<uint64_t, std::streampos> index;
    // Map of pending messages that haven't been acknowledged
    std::map<uint64_t, DtnMessage> pending;
    
    std::fstream file;
    uint64_t next_id = 1;

    void open_or_create() {
        file.open(db_path, std::ios::in | std::ios::out | std::ios::binary | std::ios::app);
        if (!file.is_open()) {
            file.open(db_path, std::ios::out | std::ios::binary);
            file.close();
            file.open(db_path, std::ios::in | std::ios::out | std::ios::binary | std::ios::app);
        }
    }
};

AtomicLedger::AtomicLedger(const std::filesystem::path& db_path) : pimpl_(std::make_unique<Impl>()) {
    pimpl_->db_path = db_path;
    pimpl_->open_or_create();
}

AtomicLedger::~AtomicLedger() {
    if (pimpl_->file.is_open()) {
        pimpl_->file.close();
    }
}

std::expected<void, std::string_view> AtomicLedger::commit_message(const DtnMessage& msg) noexcept {
    std::lock_guard<std::mutex> lock(pimpl_->mtx);
    if (!pimpl_->file.is_open()) return std::unexpected("DB not open");
    
    pimpl_->file.seekp(0, std::ios::end);
    std::streampos pos = pimpl_->file.tellp();
    
    uint64_t id = pimpl_->next_id++;
    DtnMessage to_store = msg;
    // Binary serialization of the ledger entry
    size_t data_len = to_store.payload.size();
    pimpl_->file.write(reinterpret_cast<const char*>(&id), sizeof(id));
    pimpl_->file.write(reinterpret_cast<const char*>(&data_len), sizeof(data_len));
    pimpl_->file.write(reinterpret_cast<const char*>(to_store.payload.data()), data_len);
    pimpl_->file.flush();
    
    pimpl_->index[id] = pos;
    pimpl_->pending[id] = std::move(to_store);
    
    return {};
}

std::expected<std::vector<DtnMessage>, std::string_view> AtomicLedger::extract_pending_batch(size_t max_count) {
    std::lock_guard<std::mutex> lock(pimpl_->mtx);
    std::vector<DtnMessage> batch;
    batch.reserve(std::min(max_count, pimpl_->pending.size()));
    
    for (const auto& [id, msg] : pimpl_->pending) {
        if (batch.size() >= max_count) break;
        batch.push_back(msg);
    }
    return batch;
}

std::expected<void, std::string_view> AtomicLedger::acknowledge_batch(std::span<const uint64_t> message_ids) noexcept {
    std::lock_guard<std::mutex> lock(pimpl_->mtx);
    
    // In an AOL, we would append a tombstone.
    // For this engine we just remove from pending.
    for (uint64_t id : message_ids) {
        pimpl_->pending.erase(id);
    }
    return {};
}

} // namespace nit::mesh
