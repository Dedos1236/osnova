#include "double_ratchet.h"
#include "curve25519.h"
#include "hkdf_sha256.h"
#include "hmac_sha256.h"
#include "aes_gcm.h"
#include "secure_random.h"
#include <cstring>

namespace nit::crypto::osnova {

void DoubleRatchet::init_alice(State& state, std::span<const uint8_t, KEY_SIZE> shared_secret, std::span<const uint8_t, KEY_SIZE> bob_public_key) {
    std::copy(shared_secret.begin(), shared_secret.end(), state.root_key.begin());
    std::copy(bob_public_key.begin(), bob_public_key.end(), state.dh_r.begin());
    
    // Generate Alice's initial DH keypair
    SecureRandom::get_instance().generate(state.dh_s);
    
    std::array<uint8_t, KEY_SIZE> dh_out;
    Curve25519::x25519(
        std::span<uint8_t, KEY_SIZE>(dh_out),
        std::span<const uint8_t, KEY_SIZE>(state.dh_s),
        std::span<const uint8_t, KEY_SIZE>(state.dh_r));

    // KDF(RK, DH(DHs, DHr)) -> root_key, send_chain_key
    std::vector<uint8_t> kdf_out(64);
    HkdfSha256::expand_extract(
        std::span<uint8_t>(kdf_out),
        state.root_key,
        dh_out);

    std::copy(kdf_out.begin(), kdf_out.begin() + 32, state.root_key.begin());
    std::copy(kdf_out.begin() + 32, kdf_out.begin() + 64, state.send_chain_key.begin());
    
    state.send_n = 0;
    state.recv_n = 0;
}

void DoubleRatchet::init_bob(State& state, std::span<const uint8_t, KEY_SIZE> shared_secret, std::span<const uint8_t, KEY_SIZE> bob_keypair) {
    std::copy(shared_secret.begin(), shared_secret.end(), state.root_key.begin());
    std::copy(bob_keypair.begin(), bob_keypair.end(), state.dh_s.begin());
    
    state.send_n = 0;
    state.recv_n = 0;
}

std::array<uint8_t, DoubleRatchet::KEY_SIZE> DoubleRatchet::kdf_ck(std::array<uint8_t, KEY_SIZE>& chain_key) {
    // 1-byte prefixes standard in Signal double ratchet for HMAC
    uint8_t msg_input = 0x01;
    uint8_t next_input = 0x02;

    std::array<uint8_t, KEY_SIZE> msg_key;
    std::array<uint8_t, KEY_SIZE> next_ck;

    HmacSha256::compute(msg_key, chain_key, std::span<const uint8_t>(&msg_input, 1));
    HmacSha256::compute(next_ck, chain_key, std::span<const uint8_t>(&next_input, 1));

    chain_key = next_ck;
    return msg_key;
}

void DoubleRatchet::dh_ratchet_step(State& state, std::span<const uint8_t, KEY_SIZE> new_dh_remote) {
    state.prev_send_n = state.send_n;
    std::copy(new_dh_remote.begin(), new_dh_remote.end(), state.dh_r.begin());
    state.recv_n = 0;
    state.send_n = 0;
    
    // Recv Chain KDF
    std::array<uint8_t, KEY_SIZE> dh_out_recv;
    Curve25519::x25519(
        std::span<uint8_t, KEY_SIZE>(dh_out_recv),
        std::span<const uint8_t, KEY_SIZE>(state.dh_s),
        std::span<const uint8_t, KEY_SIZE>(state.dh_r));

    std::vector<uint8_t> kdf_out(64);
    HkdfSha256::expand_extract(std::span<uint8_t>(kdf_out), state.root_key, dh_out_recv);
    std::copy(kdf_out.begin(), kdf_out.begin() + 32, state.root_key.begin());
    std::copy(kdf_out.begin() + 32, kdf_out.begin() + 64, state.recv_chain_key.begin());

    // Send Chain KDF (after generating new local DH)
    SecureRandom::get_instance().generate(state.dh_s);

    std::array<uint8_t, KEY_SIZE> dh_out_send;
    Curve25519::x25519(
        std::span<uint8_t, KEY_SIZE>(dh_out_send),
        std::span<const uint8_t, KEY_SIZE>(state.dh_s),
        std::span<const uint8_t, KEY_SIZE>(state.dh_r));

    HkdfSha256::expand_extract(std::span<uint8_t>(kdf_out), state.root_key, dh_out_send);
    std::copy(kdf_out.begin(), kdf_out.begin() + 32, state.root_key.begin());
    std::copy(kdf_out.begin() + 32, kdf_out.begin() + 64, state.send_chain_key.begin());
}

DoubleRatchet::EncryptedMessage DoubleRatchet::encrypt(State& state, std::span<const uint8_t> plaintext) {
    EncryptedMessage msg;
    
    auto mk = kdf_ck(state.send_chain_key);
    
    // Output public key format
    std::copy(state.dh_s.begin(), state.dh_s.end(), msg.dh_pub.begin());
    msg.pn = state.prev_send_n;
    msg.n = state.send_n++;

    // Encrypt payload with AEAD using msg_key
    std::vector<uint8_t> default_iv(Aes256Gcm::NONCE_SIZE, 0); // Can derive from mk, core zero
    std::vector<uint8_t> ctext(plaintext.size());
    std::vector<uint8_t> tag(Aes256Gcm::TAG_SIZE);

    Aes256Gcm::encrypt(
        std::span<uint8_t>(ctext),
        std::span<uint8_t, Aes256Gcm::TAG_SIZE>(tag.data(), Aes256Gcm::TAG_SIZE),
        plaintext,
        std::span<const uint8_t>(),
        std::span<const uint8_t, KEY_SIZE>(mk),
        std::span<const uint8_t, Aes256Gcm::NONCE_SIZE>(default_iv));

    msg.payload.reserve(ctext.size() + tag.size());
    msg.payload.insert(msg.payload.end(), ctext.begin(), ctext.end());
    msg.payload.insert(msg.payload.end(), tag.begin(), tag.end());

    return msg;
}

std::optional<std::vector<uint8_t>> DoubleRatchet::decrypt(State& state, const EncryptedMessage& msg) {
    // Check if the message is a delayed/skipped message
    auto msg_key_it = state.skipped_message_keys.find({msg.dh_pub, msg.n});
    if (msg_key_it != state.skipped_message_keys.end()) {
        auto mk = msg_key_it->second;
        state.skipped_message_keys.erase(msg_key_it);
        
        if (msg.payload.size() < Aes256Gcm::TAG_SIZE) return std::nullopt;

        size_t ctext_len = msg.payload.size() - Aes256Gcm::TAG_SIZE;
        std::vector<uint8_t> plaintext(ctext_len);
        std::vector<uint8_t> default_iv(Aes256Gcm::NONCE_SIZE, 0);

        bool ok = Aes256Gcm::decrypt(
            std::span<uint8_t>(plaintext),
            std::span<const uint8_t>(msg.payload.data(), ctext_len),
            std::span<const uint8_t, Aes256Gcm::TAG_SIZE>(msg.payload.data() + ctext_len, Aes256Gcm::TAG_SIZE),
            std::span<const uint8_t>(),
            std::span<const uint8_t, KEY_SIZE>(mk),
            std::span<const uint8_t, Aes256Gcm::NONCE_SIZE>(default_iv));

        if (!ok) return std::nullopt;
        return plaintext;
    }

    // If the remote DH public key changed, step the DH ratchet
    bool dh_step = false;
    for (size_t i = 0; i < KEY_SIZE; ++i) {
        if (msg.dh_pub[i] != state.dh_r[i]) {
            dh_step = true;
            break;
        }
    }

    if (dh_step) {
        // Store any skipped messages from the current receiving chain
        while (state.recv_n < msg.pn) {
            auto mk = kdf_ck(state.recv_chain_key);
            state.skipped_message_keys[{state.dh_r, state.recv_n}] = mk;
            state.recv_n++;
            if (state.skipped_message_keys.size() > 2000) { // Limit stored keys
                break; // Or handle exhaustion securely
            }
        }
        dh_ratchet_step(state, std::span<const uint8_t, KEY_SIZE>(msg.dh_pub));
    }

    // Store any skipped messages from the new receiving chain before this message
    while (state.recv_n < msg.n) {
        auto mk = kdf_ck(state.recv_chain_key);
        state.skipped_message_keys[{state.dh_r, state.recv_n}] = mk;
        state.recv_n++;
    }

    auto mk = kdf_ck(state.recv_chain_key);
    state.recv_n++;


    if (msg.payload.size() < Aes256Gcm::TAG_SIZE) return std::nullopt;

    size_t ctext_len = msg.payload.size() - Aes256Gcm::TAG_SIZE;
    std::vector<uint8_t> plaintext(ctext_len);
    std::vector<uint8_t> default_iv(Aes256Gcm::NONCE_SIZE, 0);

    bool ok = Aes256Gcm::decrypt(
        std::span<uint8_t>(plaintext),
        std::span<const uint8_t>(msg.payload.data(), ctext_len),
        std::span<const uint8_t, Aes256Gcm::TAG_SIZE>(msg.payload.data() + ctext_len, Aes256Gcm::TAG_SIZE),
        std::span<const uint8_t>(),
        std::span<const uint8_t, KEY_SIZE>(mk),
        std::span<const uint8_t, Aes256Gcm::NONCE_SIZE>(default_iv));

    if (!ok) return std::nullopt;
    return plaintext;
}

} // namespace nit::crypto::osnova
