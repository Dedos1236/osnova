#include "json_parser.h"
#include <sstream>
#include <iomanip>
#include <cctype>

namespace nit::osnova::json {

JsonValue::JsonValue() : type_(Type::NULL_VAL), value_(nullptr) {}
JsonValue::JsonValue(std::nullptr_t) : type_(Type::NULL_VAL), value_(nullptr) {}
JsonValue::JsonValue(bool val) : type_(Type::BOOLEAN), value_(val) {}
JsonValue::JsonValue(double val) : type_(Type::NUMBER), value_(val) {}
JsonValue::JsonValue(int val) : type_(Type::NUMBER), value_(static_cast<double>(val)) {}
JsonValue::JsonValue(long val) : type_(Type::NUMBER), value_(static_cast<double>(val)) {}
JsonValue::JsonValue(long long val) : type_(Type::NUMBER), value_(static_cast<double>(val)) {}
JsonValue::JsonValue(const char* val) : type_(Type::STRING), value_(std::string(val)) {}
JsonValue::JsonValue(const std::string& val) : type_(Type::STRING), value_(val) {}
JsonValue::JsonValue(const JsonArray& val) : type_(Type::ARRAY), value_(val) {}
JsonValue::JsonValue(const JsonObject& val) : type_(Type::OBJECT), value_(val) {}

JsonValue::Type JsonValue::type() const { return type_; }
bool JsonValue::is_null() const { return type_ == Type::NULL_VAL; }
bool JsonValue::is_bool() const { return type_ == Type::BOOLEAN; }
bool JsonValue::is_number() const { return type_ == Type::NUMBER; }
bool JsonValue::is_string() const { return type_ == Type::STRING; }
bool JsonValue::is_array() const { return type_ == Type::ARRAY; }
bool JsonValue::is_object() const { return type_ == Type::OBJECT; }

bool JsonValue::get_bool() const { return std::get<bool>(value_); }
double JsonValue::get_number() const { return std::get<double>(value_); }
const std::string& JsonValue::get_string() const { return std::get<std::string>(value_); }
const JsonArray& JsonValue::get_array() const { return std::get<JsonArray>(value_); }
const JsonObject& JsonValue::get_object() const { return std::get<JsonObject>(value_); }

std::string JsonValue::serialize(int indent, int current_indent) const {
    std::string out;
    std::string newline = (indent >= 0) ? "\n" : "";
    std::string space = (indent >= 0) ? " " : "";

    auto make_indent = [&]() -> std::string {
        if (indent < 0) return "";
        return std::string(current_indent, ' ');
    };

    switch (type_) {
        case Type::NULL_VAL: out += "null"; break;
        case Type::BOOLEAN: out += (std::get<bool>(value_) ? "true" : "false"); break;
        case Type::NUMBER: {
            double d = std::get<double>(value_);
            if (d == static_cast<long long>(d)) out += std::to_string(static_cast<long long>(d));
            else out += std::to_string(d);
            break;
        }
        case Type::STRING: {
            out += "\"";
            for (char c : std::get<std::string>(value_)) {
                if (c == '"') out += "\\\"";
                else if (c == '\\') out += "\\\\";
                else if (c == '\b') out += "\\b";
                else if (c == '\f') out += "\\f";
                else if (c == '\n') out += "\\n";
                else if (c == '\r') out += "\\r";
                else if (c == '\t') out += "\\t";
                else out += c;
            }
            out += "\"";
            break;
        }
        case Type::ARRAY: {
            const auto& arr = std::get<JsonArray>(value_);
            out += "[" + newline;
            for (size_t i = 0; i < arr.size(); ++i) {
                out += make_indent() + std::string(indent >= 0 ? indent : 0, ' ') + arr[i].serialize(indent, current_indent + (indent >= 0 ? indent : 0));
                if (i < arr.size() - 1) out += "," + newline;
                else out += newline;
            }
            out += make_indent() + "]";
            break;
        }
        case Type::OBJECT: {
            const auto& obj = std::get<JsonObject>(value_);
            out += "{" + newline;
            size_t i = 0;
            for (const auto& [k, v] : obj) {
                out += make_indent() + std::string(indent >= 0 ? indent : 0, ' ') + "\"" + k + "\":" + space + v.serialize(indent, current_indent + (indent >= 0 ? indent : 0));
                if (i < obj.size() - 1) out += "," + newline;
                else out += newline;
                ++i;
            }
            out += make_indent() + "}";
            break;
        }
    }
    return out;
}

class ParserImpl {
public:
    ParserImpl(const std::string& src) : src_(src), pos_(0) {}

    JsonValue parse() {
        skip_whitespace();
        JsonValue val = parse_value();
        skip_whitespace();
        if (pos_ < src_.length()) {
            throw JsonException("Unexpected trailing characters in JSON");
        }
        return val;
    }

private:
    std::string src_;
    size_t pos_;

    void skip_whitespace() {
        while (pos_ < src_.length() && std::isspace(src_[pos_])) {
            pos_++;
        }
    }

    char current() const {
        if (pos_ >= src_.length()) throw JsonException("Unexpected end of input");
        return src_[pos_];
    }

    void advance() {
        pos_++;
    }

    void expect(char c) {
        if (current() != c) throw JsonException(std::string("Expected '") + c + "'");
        advance();
    }

    JsonValue parse_value() {
        skip_whitespace();
        char c = current();
        if (c == 'n') return parse_null();
        if (c == 't' || c == 'f') return parse_bool();
        if (c == '-' || std::isdigit(c)) return parse_number();
        if (c == '"') return parse_string();
        if (c == '[') return parse_array();
        if (c == '{') return parse_object();
        throw JsonException("Invalid value");
    }

    JsonValue parse_null() {
        if (src_.substr(pos_, 4) == "null") {
            pos_ += 4;
            return JsonValue(nullptr);
        }
        throw JsonException("Expected null");
    }

    JsonValue parse_bool() {
        if (src_.substr(pos_, 4) == "true") {
            pos_ += 4;
            return JsonValue(true);
        } else if (src_.substr(pos_, 5) == "false") {
            pos_ += 5;
            return JsonValue(false);
        }
        throw JsonException("Expected true or false");
    }

    JsonValue parse_number() {
        size_t start = pos_;
        if (current() == '-') advance();
        while (pos_ < src_.length() && std::isdigit(current())) advance();
        if (pos_ < src_.length() && current() == '.') {
            advance();
            while (pos_ < src_.length() && std::isdigit(current())) advance();
        }
        if (pos_ < src_.length() && (current() == 'e' || current() == 'E')) {
            advance();
            if (pos_ < src_.length() && (current() == '+' || current() == '-')) advance();
            while (pos_ < src_.length() && std::isdigit(current())) advance();
        }
        try {
            return JsonValue(std::stod(src_.substr(start, pos_ - start)));
        } catch (...) {
            throw JsonException("Invalid number format");
        }
    }

    std::string parse_string_raw() {
        expect('"');
        std::string res;
        while (pos_ < src_.length() && current() != '"') {
            if (current() == '\\') {
                advance();
                char esc = current();
                switch (esc) {
                    case '"': res += '"'; break;
                    case '\\': res += '\\'; break;
                    case '/': res += '/'; break;
                    case 'b': res += '\b'; break;
                    case 'f': res += '\f'; break;
                    case 'n': res += '\n'; break;
                    case 'r': res += '\r'; break;
                    case 't': res += '\t'; break;
                    case 'u': {
                        // Very basic Unicode escape handling for structural validity
                        if (pos_ + 4 >= src_.length()) throw JsonException("Invalid unicode escape");
                        res += "\\u" + src_.substr(pos_ + 1, 4); 
                        pos_ += 4;
                        break;
                    }
                    default: throw JsonException("Invalid escape character");
                }
            } else {
                res += current();
            }
            advance();
        }
        expect('"');
        return res;
    }

    JsonValue parse_string() {
        return JsonValue(parse_string_raw());
    }

    JsonValue parse_array() {
        JsonArray arr;
        expect('[');
        skip_whitespace();
        if (current() == ']') {
            advance();
            return JsonValue(arr);
        }
        while (true) {
            arr.push_back(parse_value());
            skip_whitespace();
            if (current() == ']') {
                advance();
                break;
            }
            expect(',');
        }
        return JsonValue(arr);
    }

    JsonValue parse_object() {
        JsonObject obj;
        expect('{');
        skip_whitespace();
        if (current() == '}') {
            advance();
            return JsonValue(obj);
        }
        while (true) {
            skip_whitespace();
            std::string key = parse_string_raw();
            skip_whitespace();
            expect(':');
            obj[key] = parse_value();
            skip_whitespace();
            if (current() == '}') {
                advance();
                break;
            }
            expect(',');
        }
        return JsonValue(obj);
    }
};

JsonValue JsonParser::parse(const std::string& source) {
    ParserImpl parser(source);
    return parser.parse();
}

} // namespace nit::osnova::json
