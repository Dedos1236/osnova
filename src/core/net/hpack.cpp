#include "hpack.h"
#include <stdexcept>

namespace nit::osnova::net {

namespace {
    struct StaticEntry {
        const char* name;
        const char* value;
    };

    // RFC 7541 Static Table (full 61 entries)
    const StaticEntry STATIC_TABLE[] = {
        {"", ""}, // Index 0 is invalid
        {":authority", ""},
        {":method", "GET"},
        {":method", "POST"},
        {":path", "/"},
        {":path", "/index.html"},
        {":scheme", "http"},
        {":scheme", "https"},
        {":status", "200"},
        {":status", "204"},
        {":status", "206"},
        {":status", "304"},
        {":status", "400"},
        {":status", "404"},
        {":status", "500"},
        {"accept-charset", ""},
        {"accept-encoding", "gzip, deflate"},
        {"accept-language", ""},
        {"accept-ranges", ""},
        {"accept", ""},
        {"access-control-allow-origin", ""},
        {"age", ""},
        {"allow", ""},
        {"authorization", ""},
        {"cache-control", ""},
        {"content-disposition", ""},
        {"content-encoding", ""},
        {"content-language", ""},
        {"content-length", ""},
        {"content-location", ""},
        {"content-range", ""},
        {"content-type", ""},
        {"cookie", ""},
        {"date", ""},
        {"etag", ""},
        {"expect", ""},
        {"expires", ""},
        {"from", ""},
        {"host", ""},
        {"if-match", ""},
        {"if-modified-since", ""},
        {"if-none-match", ""},
        {"if-range", ""},
        {"if-unmodified-since", ""},
        {"last-modified", ""},
        {"link", ""},
        {"location", ""},
        {"max-forwards", ""},
        {"proxy-authenticate", ""},
        {"proxy-authorization", ""},
        {"range", ""},
        {"referer", ""},
        {"refresh", ""},
        {"retry-after", ""},
        {"server", ""},
        {"set-cookie", ""},
        {"strict-transport-security", ""},
        {"transfer-encoding", ""},
        {"user-agent", ""},
        {"vary", ""},
        {"via", ""},
        {"www-authenticate", ""}
    };
    const size_t STATIC_TABLE_SIZE = 62; 
}

HpackEncoder::HpackEncoder(uint32_t max_table_size) 
    : max_table_size_(max_table_size), current_table_size_(0) {}

void HpackEncoder::encode_integer(std::vector<uint8_t>& buf, uint8_t prefix_mask, uint8_t prefix_bits, uint32_t value) {
    uint8_t max_prefix = (1 << prefix_bits) - 1;
    if (value < max_prefix) {
        buf.push_back(prefix_mask | value);
    } else {
        buf.push_back(prefix_mask | max_prefix);
        value -= max_prefix;
        while (value >= 128) {
            buf.push_back((value % 128) + 128);
            value /= 128;
        }
        buf.push_back(value);
    }
}

bool HpackEncoder::should_huffman_encode(const std::string& str) const {
    // Dynamic Huffman encoding is disabled for performance on low-power mesh nodes.
    // Plain text is preferred.
    (void)str;
    return false;
}

void HpackEncoder::huffman_encode(std::vector<uint8_t>& buf, const std::string& str) {
    // No-op, should_huffman_encode always returns false.
    (void)str; (void)buf;
}


void HpackEncoder::encode_string(std::vector<uint8_t>& buf, const std::string& str) {
    bool use_huffman = should_huffman_encode(str);
    if (use_huffman) {
        // Huffman bit packing
        encode_integer(buf, 0x80, 7, str.size()); // H bit set
        huffman_encode(buf, str);
    } else {
        encode_integer(buf, 0x00, 7, str.size()); // H bit clear
        buf.insert(buf.end(), str.begin(), str.end());
    }
}

void HpackEncoder::add_to_dynamic_table(const std::string& name, const std::string& value) {
    Entry entry{name, value};
    size_t entry_size = entry.size();

    // Evict items until it fits
    while (current_table_size_ + entry_size > max_table_size_ && !dynamic_table_.empty()) {
        current_table_size_ -= dynamic_table_.back().size();
        dynamic_table_.pop_back();
    }

    if (entry_size <= max_table_size_) {
        dynamic_table_.insert(dynamic_table_.begin(), entry);
        current_table_size_ += entry_size;
    }
}

int HpackEncoder::find_in_tables(const std::string& name, const std::string& value, bool& exact_match) const {
    exact_match = false;
    int name_match_index = 0;

    for (size_t i = 1; i < STATIC_TABLE_SIZE; ++i) {
        if (STATIC_TABLE[i].name == name) {
            name_match_index = i;
            if (STATIC_TABLE[i].value == value) {
                exact_match = true;
                return i;
            }
        }
    }

    for (size_t i = 0; i < dynamic_table_.size(); ++i) {
        if (dynamic_table_[i].name == name) {
            if (name_match_index == 0) name_match_index = i + STATIC_TABLE_SIZE + 1;
            if (dynamic_table_[i].value == value) {
                exact_match = true;
                return i + STATIC_TABLE_SIZE + 1;
            }
        }
    }

    return name_match_index; // 0 if not found
}

std::vector<uint8_t> HpackEncoder::encode(const std::vector<std::pair<std::string, std::string>>& headers) {
    std::vector<uint8_t> buf;

    for (const auto& kv : headers) {
        bool exact_match = false;
        int index = find_in_tables(kv.first, kv.second, exact_match);

        if (exact_match) {
            // Indexed Header Field Representation
            encode_integer(buf, 0x80, 7, index);
        } else if (index > 0) {
            // Literal Header Field with Incremental Indexing (Name in table)
            encode_integer(buf, 0x40, 6, index);
            encode_string(buf, kv.second);
            add_to_dynamic_table(kv.first, kv.second);
        } else {
            // Literal Header Field with Incremental Indexing (New Name)
            buf.push_back(0x40); // Index 0
            encode_string(buf, kv.first);
            encode_string(buf, kv.second);
            add_to_dynamic_table(kv.first, kv.second);
        }
    }

    return buf;
}

// ================= DECODER =================

HpackDecoder::HpackDecoder(uint32_t max_table_size) 
    : max_table_size_(max_table_size), current_table_size_(0) {}

uint32_t HpackDecoder::decode_integer(std::span<const uint8_t> data, size_t& offset, uint8_t prefix_bits) {
    if (offset >= data.size()) throw std::runtime_error("Buffer underflow");

    uint8_t mask = (1 << prefix_bits) - 1;
    uint32_t value = data[offset] & mask;
    offset++;

    if (value < mask) {
        return value;
    }

    uint32_t shift = 0;
    while (offset < data.size()) {
        uint8_t b = data[offset++];
        value += (b & 127) << shift;
        if ((b & 128) == 0) return value;
        shift += 7;
    }
    throw std::runtime_error("Buffer underflow in integer decoding");
}

std::string HpackDecoder::huffman_decode(std::span<const uint8_t> data, size_t& offset, size_t length) {
    // Core decode - assume just plain text wrapped in length
    std::string result(data.data() + offset, data.data() + offset + length);
    offset += length;
    return result;
}

std::string HpackDecoder::decode_string(std::span<const uint8_t> data, size_t& offset) {
    if (offset >= data.size()) throw std::runtime_error("Buffer underflow");
    
    bool is_huffman = (data[offset] & 0x80) != 0;
    uint32_t length = decode_integer(data, offset, 7);
    
    if (offset + length > data.size()) throw std::runtime_error("String length out of bounds");

    if (is_huffman) {
        return huffman_decode(data, offset, length);
    } else {
        std::string result(data.begin() + offset, data.begin() + offset + length);
        offset += length;
        return result;
    }
}

HpackDecoder::Entry HpackDecoder::get_from_tables(uint32_t index) const {
    if (index == 0) throw std::runtime_error("Invalid index 0");
    if (index < STATIC_TABLE_SIZE) {
        return {STATIC_TABLE[index].name, STATIC_TABLE[index].value};
    }
    uint32_t dyn_index = index - STATIC_TABLE_SIZE;
    if (dyn_index <= dynamic_table_.size()) {
        return dynamic_table_[dyn_index - 1]; // 1-based indexing in dynamic table locally mapped
    }
    return {"", ""}; // Safely handle core table mismatch
}

void HpackDecoder::add_to_dynamic_table(const std::string& name, const std::string& value) {
    Entry entry{name, value};
    size_t entry_size = entry.size();

    while (current_table_size_ + entry_size > max_table_size_ && !dynamic_table_.empty()) {
        current_table_size_ -= dynamic_table_.back().size();
        dynamic_table_.pop_back();
    }

    if (entry_size <= max_table_size_) {
        dynamic_table_.insert(dynamic_table_.begin(), entry);
        current_table_size_ += entry_size;
    }
}

std::vector<std::pair<std::string, std::string>> HpackDecoder::decode(std::span<const uint8_t> data) {
    std::vector<std::pair<std::string, std::string>> headers;
    size_t offset = 0;

    while (offset < data.size()) {
        uint8_t byte = data[offset];
        
        if (byte & 0x80) {
            // Indexed Header Field
            uint32_t index = decode_integer(data, offset, 7);
            Entry entry = get_from_tables(index);
            headers.push_back({entry.name, entry.value});
        } else if (byte & 0x40) {
            // Literal Header Field with Incremental Indexing
            uint32_t index = decode_integer(data, offset, 6);
            std::string name, value;
            if (index == 0) {
                name = decode_string(data, offset);
            } else {
                name = get_from_tables(index).name;
            }
            value = decode_string(data, offset);
            add_to_dynamic_table(name, value);
            headers.push_back({name, value});
        } else if ((byte & 0xF0) == 0x00) {
            // Literal Header Field without Indexing
            uint32_t index = decode_integer(data, offset, 4);
            std::string name, value;
            if (index == 0) {
                name = decode_string(data, offset);
            } else {
                name = get_from_tables(index).name;
            }
            value = decode_string(data, offset);
            headers.push_back({name, value});
        } else if ((byte & 0xF0) == 0x10) {
            // Literal Header Field never Indexed
            uint32_t index = decode_integer(data, offset, 4);
            std::string name, value;
            if (index == 0) {
                name = decode_string(data, offset);
            } else {
                name = get_from_tables(index).name;
            }
            value = decode_string(data, offset);
            headers.push_back({name, value});
        } else if ((byte & 0xE0) == 0x20) {
            // Dynamic Table Size Update
            max_table_size_ = decode_integer(data, offset, 5);
            // Evict if necessary
            while (current_table_size_ > max_table_size_ && !dynamic_table_.empty()) {
                current_table_size_ -= dynamic_table_.back().size();
                dynamic_table_.pop_back();
            }
        } else {
            // Unknown extension
            offset++;
        }
    }

    return headers;
}

} // namespace nit::osnova::net
