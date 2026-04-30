#include "torrent_engine.h"
#include "bencode.h"
#include "src/core/crypto/sha256.h"
#include <iostream>

namespace nit::osnova::mesh {

TorrentEngine::TorrentEngine() = default;
TorrentEngine::~TorrentEngine() = default;

TorrentInfo TorrentEngine::parse_metadata(const std::vector<uint8_t>& bencoded_data) {
    TorrentInfo info;
    try {
        BencodeNode root = BencodeParser::parse(bencoded_data);
        if (root.type() != BencodeNode::Type::DICTIONARY) return info;
        
        auto dict = root.dict();
        if (dict.count("info") && dict.at("info").type() == BencodeNode::Type::DICTIONARY) {
            auto info_dict = dict.at("info").dict();
            
            if (info_dict.count("name")) info.name = info_dict.at("name").string();
            if (info_dict.count("piece length")) info.piece_length = info_dict.at("piece length").integer();
            if (info_dict.count("pieces")) {
                std::string pstr = info_dict.at("pieces").string();
                info.pieces_hashes.assign(pstr.begin(), pstr.end());
            }

            if (info_dict.count("length")) {
                // Single file mode
                info.files.push_back({info.name, info_dict.at("length").integer()});
            } else if (info_dict.count("files")) {
                // Multi file mode
                auto files_list = info_dict.at("files").list();
                for (const auto& file_node : files_list) {
                    if (file_node.type() == BencodeNode::Type::DICTIONARY) {
                        auto fdict = file_node.dict();
                        TorrentInfo::FileInfo fi;
                        if (fdict.count("length")) fi.length = fdict.at("length").integer();
                        
                        if (fdict.count("path")) {
                            std::string full_path;
                            auto paths = fdict.at("path").list();
                            for (const auto& p : paths) {
                                full_path += "/" + p.string();
                            }
                            fi.path = full_path;
                        }
                        info.files.push_back(fi);
                    }
                }
            }

            // Real implementation calculates SHA1/SHA256 over exactly the bencoded 'info' dictionary
            std::string info_encoded = dict.at("info").encode();
            crypto::osnova::Sha256 sha;
            sha.update(std::span<const uint8_t>(reinterpret_cast<const uint8_t*>(info_encoded.data()), info_encoded.size()));
            
            info.info_hash.resize(32);
            sha.finalize(std::span<uint8_t, 32>(info.info_hash.data(), 32));
        }
    } catch (const std::exception& e) {
        std::cerr << "Torrent Parsing Error: " << e.what() << "\n";
    }
    return info;
}

std::vector<uint8_t> TorrentEngine::build_metadata(const TorrentInfo& info, const std::string& announce_url) {
    std::map<std::string, BencodeNode> root;
    root["announce"] = BencodeNode(announce_url);
    
    std::map<std::string, BencodeNode> info_dict;
    info_dict["name"] = BencodeNode(info.name);
    info_dict["piece length"] = BencodeNode(info.piece_length);
    
    std::string hashes(info.pieces_hashes.begin(), info.pieces_hashes.end());
    info_dict["pieces"] = BencodeNode(hashes);

    if (info.files.size() == 1) {
        info_dict["length"] = BencodeNode(info.files[0].length);
    } else {
        std::vector<BencodeNode> files_list;
        for (const auto& f : info.files) {
            std::map<std::string, BencodeNode> file_node;
            file_node["length"] = BencodeNode(f.length);
            
            std::vector<BencodeNode> path_list;
            path_list.push_back(BencodeNode(f.path));
            file_node["path"] = BencodeNode(path_list);
            
            files_list.push_back(BencodeNode(file_node));
        }
        info_dict["files"] = BencodeNode(files_list);
    }

    root["info"] = BencodeNode(info_dict);

    std::string encoded = BencodeNode(root).encode();
    return std::vector<uint8_t>(encoded.begin(), encoded.end());
}

void TorrentEngine::request_piece(int piece_index, int begin, int length) {
    // Select peer from piece_availability_[piece_index] and issue RPC
}

void TorrentEngine::receive_piece(int piece_index, int begin, const std::vector<uint8_t>& block) {
    // Write to storage buffer for integration
}

void TorrentEngine::register_peer_have(const std::string& peer_id, int piece_index) {
    piece_availability_[piece_index].insert(peer_id);
}

bool TorrentEngine::verify_piece(int piece_index, const std::vector<uint8_t>& complete_piece, const std::vector<uint8_t>& pieces_hashes) const {
    if (piece_index < 0 || (piece_index * 32 + 32) > pieces_hashes.size()) {
        return false;
    }
    
    crypto::osnova::Sha256 sha;
    sha.update(std::span<const uint8_t>(complete_piece.data(), complete_piece.size()));
    
    uint8_t calculated_hash[32];
    sha.finalize(std::span<uint8_t, 32>(calculated_hash, 32));
    
    for (int i = 0; i < 32; ++i) {
        if (calculated_hash[i] != pieces_hashes[piece_index * 32 + i]) {
            return false;
        }
    }
    return true;
}

} // namespace nit::osnova::mesh
