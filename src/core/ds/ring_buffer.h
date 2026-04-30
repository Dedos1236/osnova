#pragma once

#include <vector>
#include <atomic>
#include <cstdint>
#include <span>

namespace nit::osnova::ds {

/**
 * @brief Lock-Free Zero-Copy Ring Buffer.
 * Massive concurrent throughput for packet flow between Network IO threads 
 * and Cryptography threads without locking overhead.
 */
class LockFreeRingBuffer {
public:
    explicit LockFreeRingBuffer(size_t capacity);
    ~LockFreeRingBuffer();

    LockFreeRingBuffer(const LockFreeRingBuffer&) = delete;
    LockFreeRingBuffer& operator=(const LockFreeRingBuffer&) = delete;

    /**
     * @brief Producer writes data into the buffer.
     * @return Number of bytes successfully written.
     */
    size_t write(std::span<const uint8_t> data);

    /**
     * @brief Consumer reads data out of the buffer.
     * @return Number of bytes actually read.
     */
    size_t read(std::span<uint8_t> out_data);

    size_t available_read() const;
    size_t available_write() const;

private:
    std::vector<uint8_t> buffer_;
    size_t capacity_;
    
    // alignas(64) prevents false sharing between threads on distinct cache lines
    alignas(64) std::atomic<size_t> head_{0}; // Written by Producer, read by Consumer
    alignas(64) std::atomic<size_t> tail_{0}; // Written by Consumer, read by Producer
};

} // namespace nit::osnova::ds
