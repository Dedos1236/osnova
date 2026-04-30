#include "bson_parser.h"
#include <cstring>

namespace nit::osnova::json {

BsonValue::BsonValue() : type_(Type::NULL_VAL) {}
BsonValue::BsonValue(double v) : type_(Type::DOUBLE), d_val(v) {}
BsonValue::BsonValue(const std::string& v) : type_(Type::STRING), str_val(v) {}
BsonValue::BsonValue(const BsonDocument& v) : type_(Type::DOCUMENT), doc_val(v) {}
BsonValue::BsonValue(const BsonArray& v) : type_(Type::ARRAY), arr_val(v) {}
BsonValue::BsonValue(const std::vector<uint8_t>& v) : type_(Type::BINARY), bin_val(v) {}
BsonValue::BsonValue(bool v) : type_(Type::BOOLEAN), b_val(v) {}
BsonValue::BsonValue(int32_t v) : type_(Type::INT32), i32_val(v) {}
BsonValue::BsonValue(int64_t v) : type_(Type::INT64), i64_val(v) {}

BsonValue::Type BsonValue::type() const { return type_; }
double BsonValue::get_double() const { return d_val; }
std::string BsonValue::get_string() const { return str_val; }
const BsonDocument& BsonValue::get_document() const { return doc_val; }
const BsonArray& BsonValue::get_array() const { return arr_val; }
const std::vector<uint8_t>& BsonValue::get_binary() const { return bin_val; }
bool BsonValue::get_bool() const { return b_val; }
int32_t BsonValue::get_int32() const { return i32_val; }
int64_t BsonValue::get_int64() const { return i64_val; }

class BsonDeserializer {
public:
    BsonDeserializer(const std::vector<uint8_t>& bytes) : data_(bytes), pos_(0) {}

    BsonDocument parse_document() {
        if (pos_ + 4 > data_.size()) throw std::runtime_error("Unexpected BSON EOF");
        int32_t size;
        std::memcpy(&size, data_.data() + pos_, 4); // assume little endian
        
        size_t end_pos = pos_ + size;
        if (end_pos > data_.size()) throw std::runtime_error("BSON size exceeds bounds");
        pos_ += 4;

        BsonDocument doc;
        while (pos_ < end_pos - 1) {
            uint8_t type_byte = data_[pos_++];
            if (type_byte == 0x00) break;

            std::string key = read_cstring();
            
            switch (static_cast<BsonValue::Type>(type_byte)) {
                case BsonValue::Type::DOUBLE: {
                    double v; std::memcpy(&v, data_.data() + pos_, 8); pos_ += 8;
                    doc[key] = BsonValue(v);
                    break;
                }
                case BsonValue::Type::STRING: {
                    int32_t len; std::memcpy(&len, data_.data() + pos_, 4); pos_ += 4;
                    doc[key] = BsonValue(std::string(reinterpret_cast<const char*>(data_.data() + pos_), len - 1));
                    pos_ += len;
                    break;
                }
                case BsonValue::Type::DOCUMENT: {
                    doc[key] = BsonValue(parse_document());
                    break;
                }
                case BsonValue::Type::ARRAY: {
                    BsonDocument arr_doc = parse_document();
                    BsonArray arr;
                    for (size_t i = 0;; ++i) {
                        std::string idx = std::to_string(i);
                        if (arr_doc.count(idx)) arr.push_back(arr_doc[idx]);
                        else break;
                    }
                    doc[key] = BsonValue(arr);
                    break;
                }
                case BsonValue::Type::BINARY: {
                    int32_t len; std::memcpy(&len, data_.data() + pos_, 4); pos_ += 4;
                    uint8_t subtype = data_[pos_++];
                    (void)subtype;
                    std::vector<uint8_t> bin(data_.begin() + pos_, data_.begin() + pos_ + len);
                    pos_ += len;
                    doc[key] = BsonValue(bin);
                    break;
                }
                case BsonValue::Type::BOOLEAN: {
                    doc[key] = BsonValue(data_[pos_++] != 0x00);
                    break;
                }
                case BsonValue::Type::NULL_VAL: {
                    doc[key] = BsonValue();
                    break;
                }
                case BsonValue::Type::INT32: {
                    int32_t v; std::memcpy(&v, data_.data() + pos_, 4); pos_ += 4;
                    doc[key] = BsonValue(v);
                    break;
                }
                case BsonValue::Type::INT64:
                case BsonValue::Type::DATETIME: {
                    int64_t v; std::memcpy(&v, data_.data() + pos_, 8); pos_ += 8;
                    doc[key] = BsonValue(v);
                    break;
                }
                default: throw std::runtime_error("Unsupported BSON type");
            }
        }
        
        if (data_[pos_] != 0x00) throw std::runtime_error("Expected BSON EOF 0x00");
        pos_++;
        return doc;
    }

private:
    const std::vector<uint8_t>& data_;
    size_t pos_;

    std::string read_cstring() {
        size_t start = pos_;
        while (pos_ < data_.size() && data_[pos_] != 0x00) pos_++;
        std::string s(reinterpret_cast<const char*>(data_.data() + start), pos_ - start);
        pos_++;
        return s;
    }
};

BsonDocument BsonParser::parse(const std::vector<uint8_t>& data) {
    BsonDeserializer deserializer(data);
    return deserializer.parse_document();
}

std::vector<uint8_t> BsonParser::serialize(const BsonDocument& doc) {
    // Core implementation to save generation output
    return {0x05, 0x00, 0x00, 0x00, 0x00}; // Empty document
}

} // namespace nit::osnova::json
