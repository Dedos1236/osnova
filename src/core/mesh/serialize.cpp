#include "serialize.h"
#include <cstring>
#include <bit>

namespace nit::osnova::serialize {

namespace {
    inline uint16_t bswap_16(uint16_t x) {
        return (x >> 8) | (x << 8);
    }
    inline uint32_t bswap_32(uint32_t x) {
        return (x >> 24) | ((x >> 8) & 0x0000FF00) | ((x << 8) & 0x00FF0000) | (x << 24);
    }
    inline uint64_t bswap_64(uint64_t x) {
        return (x >> 56) |
               ((x & 0x00FF000000000000ull) >> 40) |
               ((x & 0x0000FF0000000000ull) >> 24) |
               ((x & 0x000000FF00000000ull) >> 8) |
               ((x & 0x00000000FF000000ull) << 8) |
               ((x & 0x0000000000FF0000ull) << 24) |
               ((x & 0x000000000000FF00ull) << 40) |
               (x << 56);
    }

    template<typename T>
    inline T to_little_endian(T val) {
        if constexpr (std::endian::native == std::endian::little) {
            return val;
        } else {
            if constexpr (sizeof(T) == 2) return bswap_16(val);
            else if constexpr (sizeof(T) == 4) return bswap_32(val);
            else if constexpr (sizeof(T) == 8) return bswap_64(val);
        }
    }

    template<typename T>
    inline T from_little_endian(T val) {
        if constexpr (std::endian::native == std::endian::little) {
            return val;
        } else {
            if constexpr (sizeof(T) == 2) return bswap_16(val);
            else if constexpr (sizeof(T) == 4) return bswap_32(val);
            else if constexpr (sizeof(T) == 8) return bswap_64(val);
        }
    }
}

// --- WriteStream ---

void WriteStream::write_u8(uint8_t val) {
    buffer_.push_back(val);
}

void WriteStream::write_u16(uint16_t val) {
    uint16_t le = to_little_endian(val);
    uint8_t bytes[2];
    std::memcpy(bytes, &le, 2);
    buffer_.insert(buffer_.end(), bytes, bytes + 2);
}

void WriteStream::write_u32(uint32_t val) {
    uint32_t le = to_little_endian(val);
    uint8_t bytes[4];
    std::memcpy(bytes, &le, 4);
    buffer_.insert(buffer_.end(), bytes, bytes + 4);
}

void WriteStream::write_u64(uint64_t val) {
    uint64_t le = to_little_endian(val);
    uint8_t bytes[8];
    std::memcpy(bytes, &le, 8);
    buffer_.insert(buffer_.end(), bytes, bytes + 8);
}

void WriteStream::write_varint(uint64_t val) {
    while (val >= 0x80) {
        buffer_.push_back(static_cast<uint8_t>((val & 0x7F) | 0x80));
        val >>= 7;
    }
    buffer_.push_back(static_cast<uint8_t>(val));
}

void WriteStream::write_bytes(std::span<const uint8_t> data) {
    buffer_.insert(buffer_.end(), data.begin(), data.end());
}

void WriteStream::write_bytes_with_length(std::span<const uint8_t> data) {
    write_varint(data.size());
    write_bytes(data);
}

void WriteStream::write_string(const std::string& str) {
    write_bytes_with_length(std::span<const uint8_t>(reinterpret_cast<const uint8_t*>(str.data()), str.size()));
}

void WriteStream::write_object(const Serializable& obj) {
    write_u32(obj.get_type_id());
    
    // We can write it directly, but typically we might want to frame it.
    // Let's write it to a temporary buffer to get the size for framing
    std::vector<uint8_t> obj_buf;
    obj.serialize(obj_buf);
    
    write_bytes_with_length(obj_buf);
}

// --- ReadStream ---

bool ReadStream::read_u8(uint8_t& val) {
    if (offset_ + 1 > data_.size()) return false;
    val = data_[offset_++];
    return true;
}

bool ReadStream::read_u16(uint16_t& val) {
    if (offset_ + 2 > data_.size()) return false;
    uint16_t le;
    std::memcpy(&le, data_.data() + offset_, 2);
    val = from_little_endian(le);
    offset_ += 2;
    return true;
}

bool ReadStream::read_u32(uint32_t& val) {
    if (offset_ + 4 > data_.size()) return false;
    uint32_t le;
    std::memcpy(&le, data_.data() + offset_, 4);
    val = from_little_endian(le);
    offset_ += 4;
    return true;
}

bool ReadStream::read_u64(uint64_t& val) {
    if (offset_ + 8 > data_.size()) return false;
    uint64_t le;
    std::memcpy(&le, data_.data() + offset_, 8);
    val = from_little_endian(le);
    offset_ += 8;
    return true;
}

bool ReadStream::read_varint(uint64_t& val) {
    val = 0;
    uint32_t shift = 0;
    while (offset_ < data_.size() && shift < 64) {
        uint8_t byte = data_[offset_++];
        val |= static_cast<uint64_t>(byte & 0x7F) << shift;
        if ((byte & 0x80) == 0) {
            return true;
        }
        shift += 7;
    }
    return false; // Malformed varint
}

bool ReadStream::read_bytes(size_t len, std::vector<uint8_t>& out) {
    if (offset_ + len > data_.size()) return false;
    out.assign(data_.data() + offset_, data_.data() + offset_ + len);
    offset_ += len;
    return true;
}

bool ReadStream::read_bytes_with_length(std::vector<uint8_t>& out) {
    uint64_t len;
    if (!read_varint(len)) return false;
    
    // Protection against huge allocations
    if (len > 1024 * 1024 * 32) return false; // 32 MB absolute limit for single structure
    
    return read_bytes(static_cast<size_t>(len), out);
}

bool ReadStream::read_string(std::string& out) {
    std::vector<uint8_t> bytes;
    if (!read_bytes_with_length(bytes)) return false;
    out.assign(reinterpret_cast<const char*>(bytes.data()), bytes.size());
    return true;
}

bool ReadStream::read_object(Serializable& obj) {
    uint32_t type_id;
    if (!read_u32(type_id)) return false;
    
    if (type_id != obj.get_type_id()) {
        return false; // Type mismatch
    }

    std::vector<uint8_t> obj_buf;
    if (!read_bytes_with_length(obj_buf)) return false;

    size_t consumed = 0;
    if (!obj.deserialize(obj_buf, consumed)) return false;
    
    return consumed == obj_buf.size(); // Ensure fully consumed
}

} // namespace nit::osnova::serialize
