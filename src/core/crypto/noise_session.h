#pragma once

#include <string_view>
#include <cstdint>
#include <expected>
#include <span>

namespace nit::crypto {

/**
 * @brief Zero-allocation wrapper around Noise Protocol framework.
 * Focuses on Noise_IK or Noise_XX handshakes for the Mesh and L1 transit.
 * Also prepares hooks for PQ-Crypto (Kyber/Dilithium) in transit layer.
 */
class NoiseSession {
public:
    NoiseSession();
    ~NoiseSession();

    [[nodiscard]] std::expected<void, std::string_view> initialize_initiator(std::span<const std::byte> remote_static);
    [[nodiscard]] std::expected<void, std::string_view> initialize_responder();

    /**
     * @brief Encrypts payload in-place using ChaCha20Poly1305.
     * @param buffer Pre-allocated buffer with trailing space for MAC.
     * @param payload_len The current length of the plaintext.
     * @return New length (payload_len + 16 bytes MAC).
     */
    [[nodiscard]] std::expected<size_t, std::string_view> encrypt_in_place(std::span<std::byte> buffer, size_t payload_len) noexcept;

    [[nodiscard]] std::expected<size_t, std::string_view> decrypt_in_place(std::span<std::byte> buffer, size_t ciphertext_len) noexcept;

private:
    struct Impl;
    std::unique_ptr<Impl> pimpl_;
};

} // namespace nit::crypto
