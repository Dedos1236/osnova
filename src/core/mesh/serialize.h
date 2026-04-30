#pragma once

#include <cstdint>
#include <span>
#include <vector>
#include <string>
#include <memory>
#include <map>
#include <stdexcept>
#include <optional>

namespace nit::osnova::serialize {

/**
 * @brief Base class for any object that can be serialized into the OSNOVA binary format.
 */
class Serializable {
public:
    virtual ~Serializable() = default;

    /**
     * @brief Serialize this object into the given byte vector.
     */
    virtual void serialize(std::vector<uint8_t>& out) const = 0;

    /**
     * @brief Deserialize this object from the given byte span.
     * @param in Input bytes.
     * @param bytes_read Returns the number of bytes consumed.
     * @return true on success, false if the data is malformed.
     */
    virtual bool deserialize(std::span<const uint8_t> in, size_t& bytes_read) = 0;

    /**
     * @brief Get the type ID of this object (similar to MTProto constructors).
     */
    virtual uint32_t get_type_id() const = 0;
};

/**
 * @brief Primary buffer stream for writing binary data.
 */
class WriteStream {
public:
    WriteStream() = default;
    explicit WriteStream(size_t reserve_size) { buffer_.reserve(reserve_size); }

    void write_u8(uint8_t val);
    void write_u16(uint16_t val);
    void write_u32(uint32_t val);
    void write_u64(uint64_t val);
    void write_varint(uint64_t val);

    void write_bytes(std::span<const uint8_t> data);
    void write_bytes_with_length(std::span<const uint8_t> data); // TLV style
    
    void write_string(const std::string& str);
    
    void write_object(const Serializable& obj);

    const std::vector<uint8_t>& get_buffer() const { return buffer_; }
    std::vector<uint8_t> release_buffer() { return std::move(buffer_); }

private:
    std::vector<uint8_t> buffer_;
};

/**
 * @brief Primary buffer stream for reading binary data.
 */
class ReadStream {
public:
    explicit ReadStream(std::span<const uint8_t> data) : data_(data), offset_(0) {}

    bool read_u8(uint8_t& val);
    bool read_u16(uint16_t& val);
    bool read_u32(uint32_t& val);
    bool read_u64(uint64_t& val);
    bool read_varint(uint64_t& val);

    bool read_bytes(size_t len, std::vector<uint8_t>& out);
    bool read_bytes_with_length(std::vector<uint8_t>& out);

    bool read_string(std::string& out);

    bool read_object(Serializable& obj);

    size_t get_offset() const { return offset_; }
    size_t get_remaining() const { return data_.size() - offset_; }
    bool is_eof() const { return offset_ >= data_.size(); }

private:
    std::span<const uint8_t> data_;
    size_t offset_;
};

} // namespace nit::osnova::serialize
