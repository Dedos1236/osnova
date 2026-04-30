#include "afsk_modulator.h"
#include <cmath>
#include <iostream>

namespace nit::dsp {

AfskModulator::AfskModulator(uint32_t sample_rate, uint32_t baud_rate) noexcept
    : sample_rate_(sample_rate), baud_rate_(baud_rate) {}

std::vector<float> AfskModulator::modulate(std::span<const uint8_t> data) noexcept {
    size_t samples_per_bit = sample_rate_ / baud_rate_;
    size_t total_samples = data.size() * 8 * samples_per_bit;
    
    std::vector<float> pcm;
    pcm.reserve(total_samples);

    double phase_increment_mark = 2.0 * M_PI * mark_freq_ / sample_rate_;
    double phase_increment_space = 2.0 * M_PI * space_freq_ / sample_rate_;

    for (uint8_t byte : data) {
        // Modulate LSB first
        for (int i = 0; i < 8; ++i) {
            bool bit = (byte >> i) & 1;
            double increment = bit ? phase_increment_mark : phase_increment_space;

            for (size_t s = 0; s < samples_per_bit; ++s) {
                pcm.push_back(static_cast<float>(std::sin(phase_)));
                phase_ += increment;
                if (phase_ > 2.0 * M_PI) {
                    phase_ -= 2.0 * M_PI;
                }
            }
        }
    }

    return pcm;
}

AfskDemodulator::AfskDemodulator(uint32_t sample_rate, uint32_t baud_rate) noexcept
    : sample_rate_(sample_rate), baud_rate_(baud_rate), pll_step_(1.0f / (sample_rate / baud_rate)) 
{
    // Initialize Goertzel filters with a window of 1 bit width
    int window = sample_rate / baud_rate;
    goertzel_mark_.init(mark_freq_, sample_rate, window);
    goertzel_space_.init(space_freq_, sample_rate, window);
}

std::vector<uint8_t> AfskDemodulator::push_samples(std::span<const float> samples) noexcept {
    std::vector<uint8_t> decoded_packets;
    
    for (float s : samples) {
        float mag2_mark = 0;
        float mag2_space = 0;
        
        bool win_mark = goertzel_mark_.process(s, mag2_mark);
        bool win_space = goertzel_space_.process(s, mag2_space);
        
        // When a window completes, evaluate energy
        if (win_mark && win_space) {
            bool bit_val = mag2_mark > mag2_space; // Mark = 1, Space = 0
            
            // Build bytes
            if (bit_val) {
                current_byte_ |= (1 << bits_collected_);
            }
            
            bits_collected_++;
            
            if (bits_collected_ == 8) {
                // HDLC or packet boundary logic usually checks for 0x7E flags here
                // For this core AFSK implementation we accumulate raw bytes:
                packet_buffer_.push_back(current_byte_);
                
                // OSNOVA simplistic packet extraction:
                // We rely on FEC to pad precisely to BLOCK_SIZE
                // Normally an actual modem parses length headers here.
                
                bits_collected_ = 0;
                current_byte_ = 0;
            }
            
            // Advance PLL and align boundaries (soft synchronization)
            // A true physical modem correlates bit transitions to lock pll_phase_
            // Simple phase evaluation used here
        }
    }
    
    // In actual OSNOVA HDLC: Return frame when CRC passes and Frame flag hits.
    // Chunk returning here assumes framed output based on FEC decoding.
    if (packet_buffer_.size() >= 255) { // Return 1 FEC block if buffered
        std::vector<uint8_t> out = packet_buffer_;
        packet_buffer_.clear();
        return out;
    }

    return {};
}

} // namespace nit::dsp
