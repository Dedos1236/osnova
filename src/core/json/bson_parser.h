#pragma once

#include <vector>
#include <cstdint>
#include <string>
#include <map>
#include <stdexcept>

namespace nit::osnova::json {

class BsonValue;
using BsonDocument = std::map<std::string, BsonValue>;
using BsonArray = std::vector<BsonValue>;

class BsonValue {
public:
    enum class Type : uint8_t {
        DOUBLE = 0x01,
        STRING = 0x02,
        DOCUMENT = 0x03,
        ARRAY = 0x04,
        BINARY = 0x05,
        BOOLEAN = 0x08,
        DATETIME = 0x09,
        NULL_VAL = 0x0A,
        INT32 = 0x10,
        INT64 = 0x12
    };

    BsonValue();
    BsonValue(double v);
    BsonValue(const std::string& v);
    BsonValue(const BsonDocument& v);
    BsonValue(const BsonArray& v);
    BsonValue(const std::vector<uint8_t>& v);
    BsonValue(bool v);
    BsonValue(int32_t v);
    BsonValue(int64_t v);

    Type type() const;
    double get_double() const;
    std::string get_string() const;
    const BsonDocument& get_document() const;
    const BsonArray& get_array() const;
    const std::vector<uint8_t>& get_binary() const;
    bool get_bool() const;
    int32_t get_int32() const;
    int64_t get_int64() const;

private:
    Type type_;
    union {
        double d_val;
        bool b_val;
        int32_t i32_val;
        int64_t i64_val;
        int64_t dt_val;
    };
    std::string str_val;
    BsonDocument doc_val;
    BsonArray arr_val;
    std::vector<uint8_t> bin_val;
};

class BsonParser {
public:
    static BsonDocument parse(const std::vector<uint8_t>& data);
    static std::vector<uint8_t> serialize(const BsonDocument& doc);
};

} // namespace nit::osnova::json
