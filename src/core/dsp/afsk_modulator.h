#pragma once

#include <cstdint>
#include <vector>
#include <span>

namespace nit::dsp {

/**
 * @brief Audio Frequency-Shift Keying Modulator mapping bytes to PCM audio samples.
 */
class AfskModulator {
public:
    AfskModulator(uint32_t sample_rate = 48000, uint32_t baud_rate = 1200) noexcept;

    /**
     * @brief Modulates the given binary payload into 32-bit floating point PCM audio.
     */
    std::vector<float> modulate(std::span<const uint8_t> bits) noexcept;

private:
    uint32_t sample_rate_;
    uint32_t baud_rate_;
    
    // AFSK Bell 202 frequencies (1200 baud standard)
    float mark_freq_ = 1200.0f; // Bit 1
    float space_freq_ = 2200.0f; // Bit 0
    
    float phase_ = 0.0f;
};

/**
 * @brief Demodulator for extracting bits from PCM audio.
 * High-performance C++ DSP approach.
 */
class AfskDemodulator {
public:
    AfskDemodulator(uint32_t sample_rate = 48000, uint32_t baud_rate = 1200) noexcept;

    /**
     * @brief Pushes audio samples into the demodulator.
     * @return Decoded bits if a packet boundary is hit.
     */
    std::vector<uint8_t> push_samples(std::span<const float> samples) noexcept;

private:
    uint32_t sample_rate_;
    uint32_t baud_rate_;
    
    float mark_freq_ = 1200.0f;
    float space_freq_ = 2200.0f;

    struct GoertzelState {
        float q1 = 0;
        float q2 = 0;
        float coef = 0;
        int samples = 0;
        int target_samples = 0;
        
        void reset() {
            q1 = 0;
            q2 = 0;
            samples = 0;
        }
        
        void init(float target_freq, uint32_t sample_rate, int window) {
            target_samples = window;
            float k = 0.5f + (float)window * target_freq / (float)sample_rate;
            float w = (2.0f * 3.14159265359f * k) / (float)window;
            coef = 2.0f * std::cos(w);
            reset();
        }
        
        bool process(float s, float& mag2) {
            float q0 = coef * q1 - q2 + s;
            q2 = q1;
            q1 = q0;
            samples++;
            if (samples >= target_samples) {
                mag2 = q1 * q1 + q2 * q2 - coef * q1 * q2;
                reset();
                return true; // Window complete
            }
            return false;
        }
    };

    GoertzelState goertzel_mark_;
    GoertzelState goertzel_space_;

    // Delay line for correlation
    std::vector<float> delay_line_;
    
    // Clock recovery (PLL) state
    float pll_phase_ = 0;
    float pll_step_;
    
    // State machine
    bool in_sync_ = false;
    uint8_t current_byte_ = 0;
    uint8_t bits_collected_ = 0;
    std::vector<uint8_t> packet_buffer_;
};

} // namespace nit::dsp
