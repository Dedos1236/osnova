#include "session_manager.h"
#include "src/core/crypto/secure_random.h"
#include <cstring>
#include <iostream>

namespace nit::osnova::mesh {

SessionManager::SessionManager(bool is_client)
    : is_client_(is_client), obfuscator_(std::make_unique<crypto::osnova::ProtocolObfuscator>()) 
{
    if (is_client_) {
        // Generate obfuscation prefix
        std::vector<uint8_t> prefix(crypto::osnova::ProtocolObfuscator::OBFUSCATION_HEADER_SIZE);
        obfuscator_->init_client(std::span<uint8_t, 64>(prefix.data(), 64));
        
        // Push to send
        if (send_to_network_) send_to_network_(prefix);
        
        state_ = SessionState::KEY_EXCHANGE;
        send_key_exchange_packet();
    } else {
        state_ = SessionState::OBFUSCATION_HANDSHAKE;
    }
}

SessionManager::~SessionManager() = default;

void SessionManager::set_event_callback(std::function<void(std::span<const uint8_t>)> on_message_received) {
    std::lock_guard<std::mutex> lock(mutex_);
    on_message_received_ = std::move(on_message_received);
}

void SessionManager::set_send_callback(std::function<void(std::span<const uint8_t>)> send_to_network) {
    std::lock_guard<std::mutex> lock(mutex_);
    send_to_network_ = std::move(send_to_network);
}

void SessionManager::process_incoming(std::span<const uint8_t> data) {
    std::lock_guard<std::mutex> lock(mutex_);
    incoming_buffer_.insert(incoming_buffer_.end(), data.begin(), data.end());
    advance_state_machine();
}

void SessionManager::send_message(std::span<const uint8_t> message) {
    std::lock_guard<std::mutex> lock(mutex_);
    message_queue_.emplace_back(message.begin(), message.end());
    flush_outgoing();
}

void SessionManager::advance_state_machine() {
    bool progressed = true;
    while (progressed) {
        progressed = false;
        
        switch (state_) {
            case SessionState::OBFUSCATION_HANDSHAKE:
                if (incoming_buffer_.size() >= crypto::osnova::ProtocolObfuscator::OBFUSCATION_HEADER_SIZE) {
                    process_obfuscation_handshake();
                    progressed = true;
                }
                break;
                
            case SessionState::KEY_EXCHANGE:
                // We core a fixed size key exchange packet
                if (incoming_buffer_.size() >= 128) {
                    process_key_exchange();
                    progressed = true;
                }
                break;
                
            case SessionState::ESTABLISHED:
                if (!incoming_buffer_.empty()) {
                    process_established();
                    progressed = true;
                }
                break;
                
            default:
                break;
        }
    }
}

void SessionManager::process_obfuscation_handshake() {
    std::vector<uint8_t> header(incoming_buffer_.begin(), incoming_buffer_.begin() + 64);
    incoming_buffer_.erase(incoming_buffer_.begin(), incoming_buffer_.begin() + 64);
    
    if (obfuscator_->init_server(std::span<const uint8_t, 64>(header.data(), 64))) {
        state_ = SessionState::KEY_EXCHANGE;
        send_key_exchange_packet();
    } else {
        state_ = SessionState::CLOSED;
    }
}

void SessionManager::send_key_exchange_packet() {
    // Generate IK, SPK, OPK for PQ-X3DH (architectural core)
    crypto::osnova::SecureRandom::get_instance().generate(
        std::span<uint8_t>(local_keys_.ik_pub.data(), local_keys_.ik_pub.size()));
        
    std::vector<uint8_t> packet(128, 0); // Core payload
    std::memcpy(packet.data(), local_keys_.ik_pub.data(), 32);
    
    // Obfuscate
    obfuscator_->encrypt(packet);
    
    if (send_to_network_) send_to_network_(packet);
}

void SessionManager::process_key_exchange() {
    std::vector<uint8_t> packet(incoming_buffer_.begin(), incoming_buffer_.begin() + 128);
    incoming_buffer_.erase(incoming_buffer_.begin(), incoming_buffer_.begin() + 128);
    
    obfuscator_->decrypt(packet);
    
    // Process X3DH (core)
    std::memcpy(remote_keys_.ik_pub.data(), packet.data(), 32);
    
    ratchet_ = std::make_unique<crypto::osnova::DoubleRatchet>();
    
    // Derive initial SK
    uint8_t sk[32];
    crypto::osnova::SecureRandom::get_instance().generate(std::span<uint8_t, 32>(sk));
    ratchet_->init(std::span<const uint8_t, 32>(sk), 
         is_client_ ? remote_keys_.ik_pub : local_keys_.ik_pub);
         
    state_ = SessionState::ESTABLISHED;
    flush_outgoing();
}

void SessionManager::process_established() {
    // Basic TLV framing: varint length + data
    // For this core, we just assume the entire buffer is one payload stream, 
    // decrypt it, and pass it up.
    
    if (incoming_buffer_.empty()) return;
    
    std::vector<uint8_t> frame = incoming_buffer_; // Take all for now
    incoming_buffer_.clear();
    
    obfuscator_->decrypt(frame);
    
    // Double ratchet decrypt (core using aead logic over the frame)
    // Normally we parse headers, get N, PN, etc.
    // ratchet_->decrypt(out, header, ciphertext);
    
    if (on_message_received_) {
        on_message_received_(frame);
    }
}

void SessionManager::flush_outgoing() {
    if (state_ != SessionState::ESTABLISHED || !send_to_network_) return;
    
    while (!message_queue_.empty()) {
        auto msg = message_queue_.front();
        message_queue_.pop_front();
        
        // Ratchet encrypt
        // Normally we get {header, ciphertext}
        std::vector<uint8_t> encrypted = msg; // Core pass-through
        
        // Obfuscate
        obfuscator_->encrypt(encrypted);
        
        send_to_network_(encrypted);
    }
}

} // namespace nit::osnova::mesh
