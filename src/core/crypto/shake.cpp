#include "shake.h"
#include "sha3.h"

namespace nit::crypto::osnova {

void Shake::shake128(std::span<uint8_t> out, std::span<const uint8_t> in) noexcept {
    Sha3 sha;
    sha.init(Sha3::Type::SHAKE128);
    sha.update(in);
    sha.squeeze(out);
}

void Shake::shake256(std::span<uint8_t> out, std::span<const uint8_t> in) noexcept {
    Sha3 sha;
    sha.init(Sha3::Type::SHAKE256);
    sha.update(in);
    sha.squeeze(out);
}

} // namespace nit::crypto::osnova
