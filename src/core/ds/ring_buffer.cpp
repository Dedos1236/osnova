#include "ring_buffer.h"
#include <cstring>
#include <algorithm>

namespace nit::osnova::ds {

LockFreeRingBuffer::LockFreeRingBuffer(size_t capacity) {
    // Capacity must be power of 2 for fast modulo, round up
    size_t power = 1;
    while (power < capacity) power <<= 1;
    capacity_ = power;
    buffer_.resize(capacity_);
}

LockFreeRingBuffer::~LockFreeRingBuffer() = default;

size_t LockFreeRingBuffer::available_read() const {
    size_t current_head = head_.load(std::memory_order_acquire);
    size_t current_tail = tail_.load(std::memory_order_relaxed);
    return current_head - current_tail;
}

size_t LockFreeRingBuffer::available_write() const {
    size_t current_head = head_.load(std::memory_order_relaxed);
    size_t current_tail = tail_.load(std::memory_order_acquire);
    return capacity_ - (current_head - current_tail);
}

size_t LockFreeRingBuffer::write(std::span<const uint8_t> data) {
    size_t current_head = head_.load(std::memory_order_relaxed);
    size_t current_tail = tail_.load(std::memory_order_acquire);
    
    size_t free_space = capacity_ - (current_head - current_tail);
    size_t bytes_to_write = std::min(data.size(), free_space);

    if (bytes_to_write == 0) return 0;

    size_t masked_head = current_head & (capacity_ - 1);
    size_t space_until_wrap = capacity_ - masked_head;

    if (bytes_to_write <= space_until_wrap) {
        std::memcpy(buffer_.data() + masked_head, data.data(), bytes_to_write);
    } else {
        std::memcpy(buffer_.data() + masked_head, data.data(), space_until_wrap);
        std::memcpy(buffer_.data(), data.data() + space_until_wrap, bytes_to_write - space_until_wrap);
    }

    head_.store(current_head + bytes_to_write, std::memory_order_release);
    return bytes_to_write;
}

size_t LockFreeRingBuffer::read(std::span<uint8_t> out_data) {
    size_t current_head = head_.load(std::memory_order_acquire);
    size_t current_tail = tail_.load(std::memory_order_relaxed);
    
    size_t available_data = current_head - current_tail;
    size_t bytes_to_read = std::min(out_data.size(), available_data);

    if (bytes_to_read == 0) return 0;

    size_t masked_tail = current_tail & (capacity_ - 1);
    size_t space_until_wrap = capacity_ - masked_tail;

    if (bytes_to_read <= space_until_wrap) {
        std::memcpy(out_data.data(), buffer_.data() + masked_tail, bytes_to_read);
    } else {
        std::memcpy(out_data.data(), buffer_.data() + masked_tail, space_until_wrap);
        std::memcpy(out_data.data() + space_until_wrap, buffer_.data(), bytes_to_read - space_until_wrap);
    }

    tail_.store(current_tail + bytes_to_read, std::memory_order_release);
    return bytes_to_read;
}

} // namespace nit::osnova::ds
