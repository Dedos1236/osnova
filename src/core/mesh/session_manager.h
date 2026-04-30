#pragma once

#include "src/core/crypto/mtp_obfuscator.h"
#include "src/core/crypto/double_ratchet.h"
#include "src/core/crypto/pq_x3dh.h"
#include "serialize.h"

#include <cstdint>
#include <vector>
#include <memory>
#include <mutex>
#include <functional>
#include <deque>

namespace nit::osnova::mesh {

enum class SessionState {
    INITIAL,
    OBFUSCATION_HANDSHAKE,
    KEY_EXCHANGE,
    ESTABLISHED,
    SUSPENDED,
    CLOSED
};

/**
 * @brief High-level session manager handling obfuscation, X3DH, Double Ratchet, 
 * message fragmentation, reassembly, and acknowledgment.
 */
class SessionManager {
public:
    SessionManager(bool is_client);
    ~SessionManager();

    void set_event_callback(std::function<void(std::span<const uint8_t>)> on_message_received);
    void set_send_callback(std::function<void(std::span<const uint8_t>)> send_to_network);

    /**
     * @brief Process incoming raw network bytes (e.g. from TCP or UDP socket).
     */
    void process_incoming(std::span<const uint8_t> data);

    /**
     * @brief Send application data over the secure channel.
     */
    void send_message(std::span<const uint8_t> message);

    SessionState get_state() const { return state_; }

private:
    bool is_client_;
    SessionState state_ = SessionState::INITIAL;

    std::unique_ptr<crypto::osnova::ProtocolObfuscator> obfuscator_;
    std::unique_ptr<crypto::osnova::DoubleRatchet> ratchet_;

    std::function<void(std::span<const uint8_t>)> on_message_received_;
    std::function<void(std::span<const uint8_t>)> send_to_network_;

    std::vector<uint8_t> incoming_buffer_;
    std::deque<std::vector<uint8_t>> message_queue_; // pending outgoing

    // Handshake variables
    crypto::osnova::PqX3dhKeyBundle local_keys_;
    crypto::osnova::PqX3dhKeyBundle remote_keys_;
    
    std::mutex mutex_;

    void advance_state_machine();
    void process_obfuscation_handshake();
    void process_key_exchange();
    void process_established();
    void flush_outgoing();

    void send_key_exchange_packet();
};

} // namespace nit::osnova::mesh
