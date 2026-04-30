#include "lsm_tree.h"
#include <map>
#include <mutex>

namespace nit::osnova::db {

// In-Memory component of the LSM tree
class MemTable {
public:
    void put(const std::string& key, const std::vector<uint8_t>& value) {
        table_[key] = {value, false};
        size_ += key.size() + value.size() + 8;
    }

    void dlt(const std::string& key) {
        table_[key] = {{}, true}; // Tombstone
        size_ += key.size() + 8;
    }

    std::optional<std::vector<uint8_t>> get(const std::string& key) const {
        auto it = table_.find(key);
        if (it != table_.end()) {
            if (it->second.is_deleted) return std::nullopt; // Explicitly deleted
            return it->second.value;
        }
        return std::nullopt; // Not in memtable
    }

    size_t memory_usage() const { return size_; }
    void clear() { table_.clear(); size_ = 0; }

private:
    struct Record {
        std::vector<uint8_t> value;
        bool is_deleted;
    };
    std::map<std::string, Record> table_;
    size_t size_ = 0;
};

struct LsmTree::Impl {
    Options options;
    MemTable active_memtable;
    std::vector<MemTable> sstables; // In-memory flushed components
    std::mutex db_mutex;

    void check_compaction() {
        if (active_memtable.memory_usage() >= options.memtable_limit_bytes) {
            // Flush to Level 0 SSTable
            sstables.push_back(active_memtable);
            active_memtable.clear(); 
        }
    }
};

LsmTree::LsmTree(const Options& options) : pimpl_(std::make_unique<Impl>()) {
    pimpl_->options = options;
}

LsmTree::~LsmTree() = default;

bool LsmTree::put(const std::string& key, const std::vector<uint8_t>& value) {
    std::lock_guard<std::mutex> lock(pimpl_->db_mutex);
    pimpl_->active_memtable.put(key, value);
    pimpl_->check_compaction();
    return true;
}

std::optional<std::vector<uint8_t>> LsmTree::get(const std::string& key) const {
    std::lock_guard<std::mutex> lock(pimpl_->db_mutex);
    
    // 1. Check active MemTable
    auto val = pimpl_->active_memtable.get(key);
    if (val) {
        if (val->empty()) return std::nullopt; // Tombstone handling
        return val;
    }

    // 2. Check SSTables (latest first)
    for (auto it = pimpl_->sstables.rbegin(); it != pimpl_->sstables.rend(); ++it) {
        auto tbl_val = it->get(key);
        if (tbl_val) {
            if (tbl_val->empty()) return std::nullopt; // Tombstone handling
            return tbl_val;
        }
    }
    
    return std::nullopt;
}

bool LsmTree::dlt(const std::string& key) {
    std::lock_guard<std::mutex> lock(pimpl_->db_mutex);
    pimpl_->active_memtable.dlt(key);
    pimpl_->check_compaction();
    return true;
}

} // namespace nit::osnova::db
