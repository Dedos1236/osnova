#pragma once

#include <string>
#include <vector>
#include <map>
#include <set>
#include <cstdint>

namespace nit::osnova::mesh {

struct TorrentInfo {
    std::string name;
    long long piece_length;
    std::vector<uint8_t> pieces_hashes; // concatenated 20-byte SHA1 hashes
    
    struct FileInfo {
        std::string path;
        long long length;
    };
    std::vector<FileInfo> files;
    
    // Extracted overall Info Hash
    std::vector<uint8_t> info_hash;
};

/**
 * @brief OSNOVA Torrenting Engine.
 * Decentralized file distribution overlay over the P2P mesh network.
 * Implements BEP3 (BitTorrent Protocol) structure adapted for OSNOVA RPCs.
 */
class TorrentEngine {
public:
    TorrentEngine();
    ~TorrentEngine();

    /**
     * @brief Parse a .torrent file content.
     */
    static TorrentInfo parse_metadata(const std::vector<uint8_t>& bencoded_data);

    /**
     * @brief Build a metadata packet.
     */
    static std::vector<uint8_t> build_metadata(const TorrentInfo& info, const std::string& announce_url);

    /**
     * @brief Handle an incoming piece request.
     */
    void request_piece(int piece_index, int begin, int length);

    /**
     * @brief Receive piece data.
     */
    void receive_piece(int piece_index, int begin, const std::vector<uint8_t>& block);

    /**
     * @brief Register a peer that has a specific piece.
     */
    void register_peer_have(const std::string& peer_id, int piece_index);
    
    /**
     * @brief Check piece integrity based on SHA256 hashes instead of SHA1 for post-quantum safety padding.
     */
    bool verify_piece(int piece_index, const std::vector<uint8_t>& complete_piece, const std::vector<uint8_t>& pieces_hashes) const;

private:
    std::map<int, std::set<std::string>> piece_availability_;
};

} // namespace nit::osnova::mesh
