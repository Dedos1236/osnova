#include "bencode.h"
#include <stdexcept>

namespace nit::osnova::mesh {

BencodeNode::BencodeNode() : type_(Type::INTEGER), int_val_(0) {}
BencodeNode::~BencodeNode() = default;

BencodeNode::BencodeNode(long long val) : type_(Type::INTEGER), int_val_(val) {}
BencodeNode::BencodeNode(const std::string& str) : type_(Type::STRING), str_val_(str) {}
BencodeNode::BencodeNode(const std::vector<BencodeNode>& list) : type_(Type::LIST), list_val_(list) {}
BencodeNode::BencodeNode(const std::map<std::string, BencodeNode>& dict) : type_(Type::DICTIONARY), dict_val_(dict) {}

BencodeNode::Type BencodeNode::type() const { return type_; }
long long BencodeNode::integer() const { return int_val_; }
std::string BencodeNode::string() const { return str_val_; }
const std::vector<BencodeNode>& BencodeNode::list() const { return list_val_; }
const std::map<std::string, BencodeNode>& BencodeNode::dict() const { return dict_val_; }

std::string BencodeNode::encode() const {
    if (type_ == Type::INTEGER) {
        return "i" + std::to_string(int_val_) + "e";
    } else if (type_ == Type::STRING) {
        return std::to_string(str_val_.length()) + ":" + str_val_;
    } else if (type_ == Type::LIST) {
        std::string res = "l";
        for (const auto& item : list_val_) {
            res += item.encode();
        }
        res += "e";
        return res;
    } else if (type_ == Type::DICTIONARY) {
        std::string res = "d";
        for (const auto& kv : dict_val_) {
            res += std::to_string(kv.first.length()) + ":" + kv.first;
            res += kv.second.encode();
        }
        res += "e";
        return res;
    }
    return "";
}

class BencodeParserImpl {
public:
    BencodeParserImpl(const std::string& data) : data_(data), pos_(0) {}

    BencodeNode parse_next() {
        if (pos_ >= data_.size()) throw std::runtime_error("Unexpected end of bencode data");

        char c = data_[pos_];
        if (c == 'i') {
            return parse_integer();
        } else if (c == 'l') {
            return parse_list();
        } else if (c == 'd') {
            return parse_dictionary();
        } else if (c >= '0' && c <= '9') {
            return parse_string();
        } else {
            throw std::runtime_error("Invalid bencode format");
        }
    }

private:
    std::string data_;
    size_t pos_;

    BencodeNode parse_integer() {
        pos_++; // skip 'i'
        size_t end = data_.find('e', pos_);
        if (end == std::string::npos) throw std::runtime_error("Invalid integer format");
        std::string val_str = data_.substr(pos_, end - pos_);
        pos_ = end + 1;
        return BencodeNode(std::stoll(val_str));
    }

    BencodeNode parse_string() {
        size_t colon = data_.find(':', pos_);
        if (colon == std::string::npos) throw std::runtime_error("Invalid string format");
        
        long long len = std::stoll(data_.substr(pos_, colon - pos_));
        pos_ = colon + 1;
        
        if (pos_ + len > data_.size()) throw std::runtime_error("String length out of bounds");
        
        std::string val = data_.substr(pos_, len);
        pos_ += len;
        
        return BencodeNode(val);
    }

    BencodeNode parse_list() {
        pos_++; // skip 'l'
        std::vector<BencodeNode> list;
        while (pos_ < data_.size() && data_[pos_] != 'e') {
            list.push_back(parse_next());
        }
        if (pos_ >= data_.size() || data_[pos_] != 'e') throw std::runtime_error("Unclosed list");
        pos_++; // skip 'e'
        return BencodeNode(list);
    }

    BencodeNode parse_dictionary() {
        pos_++; // skip 'd'
        std::map<std::string, BencodeNode> dict;
        while (pos_ < data_.size() && data_[pos_] != 'e') {
            BencodeNode key_node = parse_string();
            BencodeNode val_node = parse_next();
            dict[key_node.string()] = val_node;
        }
        if (pos_ >= data_.size() || data_[pos_] != 'e') throw std::runtime_error("Unclosed dictionary");
        pos_++; // skip 'e'
        return BencodeNode(dict);
    }
};

BencodeNode BencodeParser::parse(const std::string& data) {
    BencodeParserImpl parser(data);
    return parser.parse_next();
}

BencodeNode BencodeParser::parse(const std::vector<uint8_t>& data) {
    std::string str(data.begin(), data.end());
    return parse(str);
}

} // namespace nit::osnova::mesh
