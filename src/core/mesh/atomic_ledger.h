#pragma once

#include <string_view>
#include <vector>
#include <span>
#include <cstdint>
#include <expected>
#include <filesystem>

namespace nit::mesh {

struct DtnMessage {
    uint64_t id;
    uint64_t sender_sn;   // Subjective Node ID
    uint64_t receiver_sn;
    std::vector<std::byte> encrypted_payload; // Noise protocol payload
    uint64_t ttl_timestamp;
};

/**
 * @brief Transactional Ledger for Delay-Tolerant Networking (L4 Autonomous Zero-Net).
 * Provides absolute survival of offline messages using SQLite and atomic `fsync+rename`.
 */
class AtomicLedger {
public:
    AtomicLedger(const std::filesystem::path& db_path);
    ~AtomicLedger();

    // Disable copy/move
    AtomicLedger(const AtomicLedger&) = delete;
    AtomicLedger& operator=(const AtomicLedger&) = delete;

    /**
     * @brief Atomically persists a DTN message. Employs WAL journal mode.
     */
    [[nodiscard]] std::expected<void, std::string_view> commit_message(const DtnMessage& msg) noexcept;

    /**
     * @brief Retrieves all pending messages when a Gateway (4G) is found.
     */
    [[nodiscard]] std::expected<std::vector<DtnMessage>, std::string_view> extract_pending_batch(size_t max_count);

    /**
     * @brief Removes messages once ACKed by the Gateway.
     */
    [[nodiscard]] std::expected<void, std::string_view> acknowledge_batch(std::span<const uint64_t> message_ids) noexcept;

private:
    struct Impl;
    std::unique_ptr<Impl> pimpl_;
};

} // namespace nit::mesh
