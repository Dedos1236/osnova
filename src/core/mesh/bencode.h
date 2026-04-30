#pragma once

#include <string>
#include <vector>
#include <memory>
#include <map>

namespace nit::osnova::mesh {

class BencodeNode {
public:
    enum class Type {
        INTEGER,
        STRING,
        LIST,
        DICTIONARY
    };

    BencodeNode();
    ~BencodeNode();

    BencodeNode(long long val);
    BencodeNode(const std::string& str);
    BencodeNode(const std::vector<BencodeNode>& list);
    BencodeNode(const std::map<std::string, BencodeNode>& dict);

    Type type() const;
    long long integer() const;
    std::string string() const;
    const std::vector<BencodeNode>& list() const;
    const std::map<std::string, BencodeNode>& dict() const;

    std::string encode() const;

private:
    Type type_;
    long long int_val_;
    std::string str_val_;
    std::vector<BencodeNode> list_val_;
    std::map<std::string, BencodeNode> dict_val_;
};

class BencodeParser {
public:
    static BencodeNode parse(const std::string& data);
    static BencodeNode parse(const std::vector<uint8_t>& data);
};

} // namespace nit::osnova::mesh
