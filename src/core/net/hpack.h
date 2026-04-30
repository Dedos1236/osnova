#pragma once

#include <vector>
#include <string>
#include <map>
#include <cstdint>
#include <span>
#include <utility>

namespace nit::osnova::net {

/**
 * @brief HPACK (RFC 7541) Header Compression for HTTP/2.
 * Crucial for fast bidirectional signaling across OSNOVA QUIC/HTTP2 links.
 * Highly compresses repetitive text headers using static dictionaries, 
 * dynamic state tables, and Huffman coding.
 */
class HpackEncoder {
public:
    explicit HpackEncoder(uint32_t max_table_size = 4096);
    ~HpackEncoder() = default;

    /**
     * @brief Encode an entire list of headers into binary HPACK format.
     */
    std::vector<uint8_t> encode(const std::vector<std::pair<std::string, std::string>>& headers);

private:
    uint32_t max_table_size_;
    uint32_t current_table_size_;
    
    struct Entry {
        std::string name;
        std::string value;
        size_t size() const { return name.size() + value.size() + 32; }
    };

    std::vector<Entry> dynamic_table_;

    void encode_integer(std::vector<uint8_t>& buf, uint8_t prefix_mask, uint8_t prefix_bits, uint32_t value);
    void encode_string(std::vector<uint8_t>& buf, const std::string& str);
    
    // Huffman encoding logic
    bool should_huffman_encode(const std::string& str) const;
    void huffman_encode(std::vector<uint8_t>& buf, const std::string& str);

    void add_to_dynamic_table(const std::string& name, const std::string& value);
    int find_in_tables(const std::string& name, const std::string& value, bool& exact_match) const;
};

class HpackDecoder {
public:
    explicit HpackDecoder(uint32_t max_table_size = 4096);
    ~HpackDecoder() = default;

    /**
     * @brief Decode a binary HPACK block into a list of headers.
     */
    std::vector<std::pair<std::string, std::string>> decode(std::span<const uint8_t> data);

private:
    uint32_t max_table_size_;
    uint32_t current_table_size_;

    struct Entry {
        std::string name;
        std::string value;
        size_t size() const { return name.size() + value.size() + 32; }
    };

    std::vector<Entry> dynamic_table_;

    uint32_t decode_integer(std::span<const uint8_t> data, size_t& offset, uint8_t prefix_bits);
    std::string decode_string(std::span<const uint8_t> data, size_t& offset);
    
    std::string huffman_decode(std::span<const uint8_t> data, size_t& offset, size_t length);

    void add_to_dynamic_table(const std::string& name, const std::string& value);
    Entry get_from_tables(uint32_t index) const;
};

} // namespace nit::osnova::net
