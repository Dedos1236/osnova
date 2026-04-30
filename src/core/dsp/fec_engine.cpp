#include "fec_engine.h"
#include <cstring>
#include <cmath>
#include <algorithm>

namespace nit::dsp {

FecEngine::FecEngine() noexcept {
    init_galois_tables();
    init_generator_poly();
}

void FecEngine::init_galois_tables() noexcept {
    uint8_t x = 1;
    for (int i = 0; i < 255; i++) {
        gf_exp[i] = x;
        gf_log[x] = i;
        // x^8 + x^4 + x^3 + x^2 + 1 (1 0001 1101 -> 0x11D)
        // Since we are working with 8 bits, we check the overflow bit
        bool overflow = (x & 0x80) != 0;
        x <<= 1;
        if (overflow) {
            x ^= 0x1D; // The lower 8 bits of 0x11D
        }
    }
    for (int i = 255; i < 512; i++) {
        gf_exp[i] = gf_exp[i - 255];
    }
    gf_log[0] = 0; // Not mathematically defined, but handled via ifs
}

uint8_t FecEngine::gf_mul(uint8_t x, uint8_t y) const noexcept {
    if (x == 0 || y == 0) return 0;
    return gf_exp[gf_log[x] + gf_log[y]];
}

uint8_t FecEngine::gf_div(uint8_t x, uint8_t y) const noexcept {
    if (y == 0) return 0; // Div by zero
    if (x == 0) return 0;
    int index = gf_log[x] - gf_log[y] + 255;
    return gf_exp[index];
}

uint8_t FecEngine::gf_inv(uint8_t x) const noexcept {
    if (x == 0) return 0; // Div by zero
    return gf_exp[255 - gf_log[x]];
}

void FecEngine::init_generator_poly() noexcept {
    // generator_poly is the product of (x - a^i) for i = 0 to PARITY_SIZE-1
    std::memset(generator_poly, 0, sizeof(generator_poly));
    generator_poly[0] = 1;
    
    for (size_t i = 0; i < PARITY_SIZE; i++) {
        uint8_t current_root = gf_exp[i]; // a^i (in standard representation often just i+1 if root is 2^(i+1))
        
        // Multiply generator_poly by (x - current_root)
        // generator_poly(x) = generator_poly(x) * x - generator_poly(x) * current_root
        // In GF(2^8) addition and subtraction are XOR
        uint8_t next_poly[PARITY_SIZE + 1] = {0};
        
        for (size_t j = 0; j <= i; j++) {
            // generator_poly(x) * current_root
            uint8_t term2 = gf_mul(generator_poly[j], current_root);
            // generator_poly(x) * x -> shift array by 1
            uint8_t term1 = (j == 0) ? 0 : generator_poly[j - 1];
            next_poly[j] = term1 ^ term2;
        }
        next_poly[i + 1] = generator_poly[i];
        
        std::memcpy(generator_poly, next_poly, sizeof(generator_poly));
    }
}

void FecEngine::encode_block(const uint8_t* in_data, uint8_t* out_block) noexcept {
    std::memcpy(out_block, in_data, DATA_SIZE);
    
    uint8_t parity[PARITY_SIZE] = {0};
    
    for (size_t i = 0; i < DATA_SIZE; i++) {
        uint8_t feedback = out_block[i] ^ parity[PARITY_SIZE - 1];
        
        for (size_t j = PARITY_SIZE - 1; j > 0; j--) {
            parity[j] = parity[j - 1] ^ gf_mul(generator_poly[j], feedback);
        }
        parity[0] = gf_mul(generator_poly[0], feedback);
    }
    
    for (size_t i = 0; i < PARITY_SIZE; i++) {
        out_block[DATA_SIZE + i] = parity[PARITY_SIZE - 1 - i];
    }
}

bool FecEngine::decode_block(const uint8_t* in_block, uint8_t* out_data) noexcept {
    uint8_t synd[PARITY_SIZE];
    bool has_errors = false;
    
    // Calculate syndromes
    for (size_t i = 0; i < PARITY_SIZE; i++) {
        uint8_t sum = 0;
        for (size_t j = 0; j < BLOCK_SIZE; j++) {
            sum = gf_mul(sum, gf_exp[i]) ^ in_block[j];
        }
        synd[i] = sum;
        if (sum != 0) has_errors = true;
    }
    
    if (!has_errors) {
        std::memcpy(out_data, in_block, DATA_SIZE);
        return true;
    }
    
    // Berlekamp-Massey
    uint8_t error_locator[PARITY_SIZE + 1] = {1};
    uint8_t old_locator[PARITY_SIZE + 1] = {1};
    size_t num_errors = 0;
    
    for (size_t i = 0; i < PARITY_SIZE; i++) {
        uint8_t delta = synd[i];
        for (size_t j = 1; j <= num_errors; j++) {
            delta ^= gf_mul(error_locator[j], synd[i - j]);
        }
        
        // Shift old locator
        for (size_t j = PARITY_SIZE; j > 0; j--) {
            old_locator[j] = old_locator[j - 1];
        }
        old_locator[0] = 0;
        
        if (delta != 0) {
            uint8_t prev_locator[PARITY_SIZE + 1];
            std::memcpy(prev_locator, error_locator, sizeof(error_locator));
            
            for (size_t j = 0; j <= PARITY_SIZE; j++) {
                error_locator[j] ^= gf_mul(delta, old_locator[j]);
            }
            
            if (2 * num_errors <= i) {
                num_errors = i + 1 - num_errors;
                uint8_t inv_delta = gf_inv(delta);
                for (size_t j = 0; j <= PARITY_SIZE; j++) {
                    old_locator[j] = gf_mul(prev_locator[j], inv_delta);
                }
            }
        }
    }
    
    if (num_errors * 2 > PARITY_SIZE) return false; // Too many errors
    
    // Chien Search (Find roots of error locator polynomial)
    uint8_t error_pos[PARITY_SIZE];
    size_t found_errors = 0;
    for (size_t i = 0; i < BLOCK_SIZE; i++) {
        uint8_t sum = 0;
        uint8_t inv_root = gf_exp[255 - i]; // a^-i essentially
        uint8_t current_term = 1;
        
        for (size_t j = 0; j <= num_errors; j++) {
            sum ^= gf_mul(error_locator[j], current_term);
            current_term = gf_mul(current_term, inv_root);
        }
        
        if (sum == 0) {
            error_pos[found_errors++] = BLOCK_SIZE - 1 - i;
        }
    }
    
    if (found_errors != num_errors) return false;
    
    // Forney Algorithm (Calculate error magnitudes)
    // First calculate the error evaluator polynomial
    uint8_t evaluator[PARITY_SIZE] = {0};
    for (size_t i = 0; i < num_errors; i++) {
        uint8_t sum = synd[i];
        for (size_t j = 1; j <= i; j++) {
            sum ^= gf_mul(error_locator[j], synd[i - j]);
        }
        evaluator[i] = sum;
    }
    
    // Calculate formal derivative of error locator polynomial (odd terms stay, even drop)
    uint8_t derivative[PARITY_SIZE] = {0};
    for (size_t i = 1; i <= num_errors; i += 2) {
        derivative[i - 1] = error_locator[i];
    }
    
    // Apply correction
    uint8_t corrected_block[BLOCK_SIZE];
    std::memcpy(corrected_block, in_block, BLOCK_SIZE);
    
    for (size_t i = 0; i < num_errors; i++) {
        int pos = error_pos[i];
        uint8_t root_inv = gf_exp[255 - (BLOCK_SIZE - 1 - pos)]; // a^-(255-1-pos) = a^(pos) really (mod 255)
        
        uint8_t num = 0;
        uint8_t current_term = 1;
        for (size_t j = 0; j < num_errors; j++) {
            num ^= gf_mul(evaluator[j], current_term);
            current_term = gf_mul(current_term, root_inv);
        }
        
        uint8_t den = 0;
        current_term = 1;
        for (size_t j = 0; j < num_errors; j += 2) { // Evaluate derivative
            den ^= gf_mul(error_locator[j + 1], current_term);
            current_term = gf_mul(current_term, gf_mul(root_inv, root_inv));
        }
        
        // Magnitude = num / den * root_inv (if we defined symptoms slightly differently, sometimes just num/den)
        // Adjusted for standard Forney
        uint8_t p = gf_div(num, den); 
        corrected_block[pos] ^= p; 
    }
    
    std::memcpy(out_data, corrected_block, DATA_SIZE);
    return true;
}

std::vector<uint8_t> FecEngine::encode(std::span<const uint8_t> input) noexcept {
    size_t num_blocks = (input.size() + DATA_SIZE - 1) / DATA_SIZE;
    std::vector<uint8_t> output(num_blocks * BLOCK_SIZE, 0);

    for (size_t i = 0; i < num_blocks; ++i) {
        size_t offset = i * DATA_SIZE;
        size_t available = input.size() - offset;
        
        uint8_t temp_data[DATA_SIZE] = {0}; // Zero padded
        size_t copy_len = (available < DATA_SIZE) ? available : DATA_SIZE;
        
        std::memcpy(temp_data, input.data() + offset, copy_len);
        
        encode_block(temp_data, output.data() + (i * BLOCK_SIZE));
    }

    return output;
}

std::vector<uint8_t> FecEngine::decode(std::span<const uint8_t> input, bool& success) noexcept {
    success = true;
    if (input.size() % BLOCK_SIZE != 0) {
        success = false;
        return {};
    }

    size_t num_blocks = input.size() / BLOCK_SIZE;
    std::vector<uint8_t> output(num_blocks * DATA_SIZE, 0);

    for (size_t i = 0; i < num_blocks; ++i) {
        if (!decode_block(input.data() + (i * BLOCK_SIZE), output.data() + (i * DATA_SIZE))) {
            success = false;
            return {};
        }
    }

    return output;
}

} // namespace nit::dsp
