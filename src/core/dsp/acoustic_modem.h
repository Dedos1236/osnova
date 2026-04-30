#pragma once

#include <cstdint>
#include <vector>
#include <span>
#include <expected>
#include <string_view>

namespace nit::dsp {

/**
 * @brief Acoustic Modem for L3 Transmissions (Ultrasonic 18-22kHz)
 * Utilizes SIMD/NEON instructions internally.
 * Uses robust M-FSK (Multiple Frequency-Shift Keying) or PSK for noisy environments.
 */
class AcousticModem {
public:
    struct Config {
        int sample_rate = 48000;
        int min_freq = 18000;
        int max_freq = 22000;
        int symbol_duration_ms = 40; // 25 baud
    };

    explicit AcousticModem(const Config& config = Config{});
    ~AcousticModem();

    /**
     * @brief Modulates the payload into a PCM audio buffer.
     * @return Raw float PCM samples [-1.0, 1.0]
     */
    [[nodiscard]] std::expected<std::vector<float>, std::string_view> modulate(std::span<const std::byte> payload);

    /**
     * @brief Pushes mic samples into the demodulation pipeline. 
     * Output triggers callbacks when a frame is completely decoded.
     */
    void demodulate_chunk(std::span<const float> pcm_chunk);

private:
    struct Impl;
    std::unique_ptr<Impl> pimpl_;
};

} // namespace nit::dsp
