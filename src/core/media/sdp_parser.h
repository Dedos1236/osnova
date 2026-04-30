#pragma once

#include <string>
#include <vector>
#include <map>
#include <optional>

namespace nit::osnova::media {

/**
 * @brief WebRTC Session Description Protocol (SDP) parser/builder.
 * This handles RFC 4566 parsing for establishing WebRTC peer-to-peer 
 * streaming capabilities within OSNOVA.
 */
class SdpParser {
public:
    struct Attribute {
        std::string name;
        std::optional<std::string> value;
    };

    struct MediaDescription {
        std::string type; // audio, video, data
        int port;
        std::string protocol;
        std::vector<int> payload_types;
        std::string information;
        std::vector<std::string> connections;
        std::vector<Attribute> attributes;
    };

    struct SessionDescription {
        int version;
        std::string origin;
        std::string session_name;
        std::string information;
        std::string uri;
        std::string email;
        std::string phone;
        std::string connection;
        std::vector<std::string> bandwidths;
        std::vector<std::string> times;
        std::string timezone;
        std::string encryption_key;
        std::vector<Attribute> attributes;
        std::vector<MediaDescription> media;
    };

    SdpParser() = default;

    /**
     * @brief Parse a raw SDP string into the SessionDescription structure.
     */
    static std::optional<SessionDescription> parse(const std::string& sdp);

    /**
     * @brief Build a raw SDP string from the SessionDescription structure.
     */
    static std::string build(const SessionDescription& session);

private:
    static std::vector<std::string> split(const std::string& s, char delimiter);
};

} // namespace nit::osnova::media
