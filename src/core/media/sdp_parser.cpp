#include "sdp_parser.h"
#include <sstream>

namespace nit::osnova::media {

std::vector<std::string> SdpParser::split(const std::string& s, char delimiter) {
    std::vector<std::string> tokens;
    std::string token;
    std::istringstream tokenStream(s);
    while (std::getline(tokenStream, token, delimiter)) {
        if (!token.empty() && token.back() == '\r') {
            token.pop_back();
        }
        tokens.push_back(token);
    }
    return tokens;
}

std::optional<SdpParser::SessionDescription> SdpParser::parse(const std::string& sdp) {
    auto lines = split(sdp, '\n');
    if (lines.empty()) return std::nullopt;

    SessionDescription session;
    MediaDescription* current_media = nullptr;

    for (const auto& line : lines) {
        if (line.size() < 2 || line[1] != '=') continue;

        char type = line[0];
        std::string val = line.substr(2);

        if (type == 'm') {
            session.media.emplace_back();
            current_media = &session.media.back();
            
            auto parts = split(val, ' ');
            if (parts.size() >= 3) {
                current_media->type = parts[0];
                current_media->port = std::stoi(parts[1]);
                current_media->protocol = parts[2];
                for (size_t i = 3; i < parts.size(); ++i) {
                    current_media->payload_types.push_back(std::stoi(parts[i]));
                }
            }
            continue;
        }

        if (current_media) {
            // Media level
            switch (type) {
                case 'i': current_media->information = val; break;
                case 'c': current_media->connections.push_back(val); break;
                case 'a': {
                    size_t colon = val.find(':');
                    if (colon != std::string::npos) {
                        current_media->attributes.push_back({val.substr(0, colon), val.substr(colon + 1)});
                    } else {
                        current_media->attributes.push_back({val, std::nullopt});
                    }
                    break;
                }
            }
        } else {
            // Session level
            switch (type) {
                case 'v': session.version = std::stoi(val); break;
                case 'o': session.origin = val; break;
                case 's': session.session_name = val; break;
                case 'i': session.information = val; break;
                case 'u': session.uri = val; break;
                case 'e': session.email = val; break;
                case 'p': session.phone = val; break;
                case 'c': session.connection = val; break;
                case 'b': session.bandwidths.push_back(val); break;
                case 't': session.times.push_back(val); break;
                case 'z': session.timezone = val; break;
                case 'k': session.encryption_key = val; break;
                case 'a': {
                    size_t colon = val.find(':');
                    if (colon != std::string::npos) {
                        session.attributes.push_back({val.substr(0, colon), val.substr(colon + 1)});
                    } else {
                        session.attributes.push_back({val, std::nullopt});
                    }
                    break;
                }
            }
        }
    }

    return session;
}

std::string SdpParser::build(const SessionDescription& session) {
    std::ostringstream out;

    out << "v=" << session.version << "\r\n";
    out << "o=" << (session.origin.empty() ? "-" : session.origin) << "\r\n";
    out << "s=" << (session.session_name.empty() ? "-" : session.session_name) << "\r\n";
    
    if (!session.information.empty()) out << "i=" << session.information << "\r\n";
    if (!session.uri.empty()) out << "u=" << session.uri << "\r\n";
    if (!session.email.empty()) out << "e=" << session.email << "\r\n";
    if (!session.phone.empty()) out << "p=" << session.phone << "\r\n";
    if (!session.connection.empty()) out << "c=" << session.connection << "\r\n";
    
    for (const auto& b : session.bandwidths) out << "b=" << b << "\r\n";
    
    if (session.times.empty()) {
        out << "t=0 0\r\n";
    } else {
        for (const auto& t : session.times) out << "t=" << t << "\r\n";
    }
    
    if (!session.timezone.empty()) out << "z=" << session.timezone << "\r\n";
    if (!session.encryption_key.empty()) out << "k=" << session.encryption_key << "\r\n";

    for (const auto& attr : session.attributes) {
        out << "a=" << attr.name;
        if (attr.value) out << ":" << *attr.value;
        out << "\r\n";
    }

    for (const auto& m : session.media) {
        out << "m=" << m.type << " " << m.port << " " << m.protocol;
        for (int pt : m.payload_types) out << " " << pt;
        out << "\r\n";

        if (!m.information.empty()) out << "i=" << m.information << "\r\n";
        for (const auto& c : m.connections) out << "c=" << c << "\r\n";
        
        for (const auto& attr : m.attributes) {
            out << "a=" << attr.name;
            if (attr.value) out << ":" << *attr.value;
            out << "\r\n";
        }
    }

    return out.str();
}

} // namespace nit::osnova::media
