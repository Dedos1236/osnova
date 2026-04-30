#include "audio_modem.h"

namespace nit::dsp {

void AudioModem::transmit_data(std::span<const uint8_t> data, std::function<void(std::vector<float>)> pcm_out_cb) {
    std::lock_guard<std::mutex> lock(mtx_);
    
    // 1. Appends FEC parity
    auto fec_encoded = fec_.encode(data);
    
    // 2. Modulate to Audio
    auto pcm_buffer = mod_.modulate(std::span<const uint8_t>(fec_encoded.data(), fec_encoded.size()));
    
    // 3. Callback to platform hardware (WASAPI, ALSA, CoreAudio, or WASM WebAudio API)
    if (pcm_out_cb) {
        pcm_out_cb(std::move(pcm_buffer));
    }
}

void AudioModem::receive_audio(std::span<const float> pcm_samples, std::function<void(std::vector<uint8_t>)> data_in_cb) {
    std::lock_guard<std::mutex> lock(mtx_);
    
    // 1. Demodulate audio to bitstream
    auto raw_bits = demod_.push_samples(pcm_samples);
    
    if (raw_bits.empty()) return;

    // 2. FEC correction
    bool success = false;
    auto corrected_data = fec_.decode(std::span<const uint8_t>(raw_bits.data(), raw_bits.size()), success);

    // 3. Pass packet
    if (success && data_in_cb) {
        data_in_cb(std::move(corrected_data));
    }
}

} // namespace nit::dsp
