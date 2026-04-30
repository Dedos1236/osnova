#pragma once

#include "osnova_crypto_engine.h"
#include <memory>
#include <string_view>

namespace nit::crypto::osnova {

/**
 * @brief OSNOVA TrustZone Enclave Interface.
 * This class interfaces with the actual ARM TrustZone / Android Keystore / iOS Secure Enclave.
 * It prevents the application memory from ever seeing the native secret keys.
 */
class SecureEnclave {
public:
    SecureEnclave();
    ~SecureEnclave();

    // Disable copy/move to prevent unauthorized memory slicing
    SecureEnclave(const SecureEnclave&) = delete;
    SecureEnclave& operator=(const SecureEnclave&) = delete;

    /**
     * @brief Generates keys completely isolated within the TPM/Enclave.
     */
    [[nodiscard]] std::expected<void, CryptoError> provision_hardware_keys() noexcept;

    /**
     * @brief Exports the public portion of the hybrid keys for distribution.
     * Note: Secret keys can NEVER be exported by design.
     */
    [[nodiscard]] std::expected<HybridPublicKey, CryptoError> export_public_key() const noexcept;

    /**
     * @brief Signs a payload securely within the enclave.
     */
    [[nodiscard]] std::expected<std::vector<std::byte>, CryptoError> sign_payload_ed25519(
        std::span<const std::byte> payload) noexcept;

    /**
     * @brief Performs ECDH and Kyber Decapsulation STRICTLY within the enclave bounds.
     * The OSNOVA protocol mandates that decapsulation never exposes the resultant symmetric key
     * to the userland C++ app, but instead registers it into a session context inside the enclave.
     */
    [[nodiscard]] std::expected<uint64_t, CryptoError> secure_decapsulate(
        const HybridCiphertext& incoming_ct) noexcept;

private:
    struct Impl;
    std::unique_ptr<Impl> pimpl_;
};

} // namespace nit::crypto::osnova
