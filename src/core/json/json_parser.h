#pragma once

#include <string>
#include <vector>
#include <map>
#include <memory>
#include <stdexcept>
#include <variant>

namespace nit::osnova::json {

class JsonValue;

using JsonObject = std::map<std::string, JsonValue>;
using JsonArray = std::vector<JsonValue>;

class JsonValue {
public:
    enum class Type {
        NULL_VAL,
        BOOLEAN,
        NUMBER,
        STRING,
        ARRAY,
        OBJECT
    };

    JsonValue();
    JsonValue(std::nullptr_t);
    JsonValue(bool val);
    JsonValue(double val);
    JsonValue(int val);
    JsonValue(long val);
    JsonValue(long long val);
    JsonValue(const char* val);
    JsonValue(const std::string& val);
    JsonValue(const JsonArray& val);
    JsonValue(const JsonObject& val);

    Type type() const;
    bool is_null() const;
    bool is_bool() const;
    bool is_number() const;
    bool is_string() const;
    bool is_array() const;
    bool is_object() const;

    bool get_bool() const;
    double get_number() const;
    const std::string& get_string() const;
    const JsonArray& get_array() const;
    const JsonObject& get_object() const;

    std::string serialize(int indent = -1, int current_indent = 0) const;

private:
    Type type_;
    std::variant<std::nullptr_t, bool, double, std::string, JsonArray, JsonObject> value_;
};

class JsonParser {
public:
    static JsonValue parse(const std::string& source);
};

class JsonException : public std::runtime_error {
public:
    explicit JsonException(const std::string& msg) : std::runtime_error(msg) {}
};

} // namespace nit::osnova::json
