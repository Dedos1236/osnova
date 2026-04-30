#pragma once

#include "afsk_modulator.h"
#include "fec_engine.h"
#include <mutex>
#include <functional>

namespace nit::dsp {

/**
 * @brief High level Audio Modem wrapping FEC and AFSK.
 */
class AudioModem {
public:
    AudioModem() = default;

    /**
     * @brief Configures modem to broadcast encoded buffers.
     */
    void transmit_data(std::span<const uint8_t> data, std::function<void(std::vector<float>)> pcm_out_cb);

    /**
     * @brief Feed PCM audio from microphone into modem.
     */
    void receive_audio(std::span<const float> pcm_samples, std::function<void(std::vector<uint8_t>)> data_in_cb);

private:
    std::mutex mtx_;
    AfskModulator mod_;
    AfskDemodulator demod_;
    FecEngine fec_;
};

} // namespace nit::dsp
