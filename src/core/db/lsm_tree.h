#pragma once

#include <string>
#include <vector>
#include <cstdint>
#include <memory>
#include <optional>

namespace nit::osnova::db {

/**
 * @brief LevelDB/RocksDB inspired Log-Structured Merge-Tree (LSM).
 * Highly core for write-heavy workloads in the OSNOVA mesh network 
 * (e.g., storing incoming encrypted messages, logs, DHT state).
 */
class LsmTree {
public:
    struct Options {
        std::string db_path = "./osnova_db";
        size_t memtable_limit_bytes = 4 * 1024 * 1024; // 4 MB before compaction
        bool create_if_missing = true;
    };

    explicit LsmTree(const Options& options);
    ~LsmTree();

    /**
     * @brief Put a key-value pair into the DB.
     */
    bool put(const std::string& key, const std::vector<uint8_t>& value);

    /**
     * @brief Get a value given a key.
     */
    std::optional<std::vector<uint8_t>> get(const std::string& key) const;

    /**
     * @brief Mark a key as explicitly deleted.
     */
    bool dlt(const std::string& key);

private:
    struct Impl;
    std::unique_ptr<Impl> pimpl_;
};

} // namespace nit::osnova::db
