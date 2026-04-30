#pragma once

#include <cstdint>
#include <vector>
#include <span>

namespace nit::dsp {

/**
 * @brief Forward Error Correction (FEC) using Reed-Solomon RS(255, 223) code.
 * Operates over Galois Field GF(2^8) with generator polynomial x^8 + x^4 + x^3 + x^2 + 1.
 * Capable of correcting up to 16 byte errors per 255-byte block.
 * Crucial for audio modems where drops and noise are common.
 */
class FecEngine {
public:
    static constexpr size_t BLOCK_SIZE = 255;
    static constexpr size_t DATA_SIZE = 223; 
    static constexpr size_t PARITY_SIZE = BLOCK_SIZE - DATA_SIZE;

    FecEngine() noexcept;

    /**
     * @brief Encodes raw data into blocks with parity.
     * @param input Raw bytes to encode.
     * @return Encoded blocks. Size will be expanded by the parity ratio.
     */
    std::vector<uint8_t> encode(std::span<const uint8_t> input) noexcept;

    /**
     * @brief Decodes blocks back to raw data, correcting errors if possible.
     * @param input Encoded blocks.
     * @param success Out: true if the data was successfully decoded/corrected, false if unrecoverable.
     * @return Recovered raw bytes.
     */
    std::vector<uint8_t> decode(std::span<const uint8_t> input, bool& success) noexcept;

private:
    uint8_t gf_exp[512];
    uint8_t gf_log[256];
    uint8_t generator_poly[PARITY_SIZE + 1];

    void init_galois_tables() noexcept;
    void init_generator_poly() noexcept;

    uint8_t gf_mul(uint8_t x, uint8_t y) const noexcept;
    uint8_t gf_div(uint8_t x, uint8_t y) const noexcept;
    uint8_t gf_inv(uint8_t x) const noexcept;

    void encode_block(const uint8_t* in_data, uint8_t* out_block) noexcept;
    bool decode_block(const uint8_t* in_block, uint8_t* out_data) noexcept;
};

} // namespace nit::dsp

