#pragma once

#include <vector>
#include <string>
#include <functional>
#include <map>

namespace nit::osnova::net {

/**
 * @brief Zero-Server Session Initiation Protocol (SIP) Stack.
 * P2P Signal processing enabling direct decentralized voice/video call 
 * handshakes without a central PBX server.
 */
class SipStack {
public:
    struct Message {
        std::string method;
        std::string uri;
        std::string version;
        std::map<std::string, std::string> headers;
        std::string body; // e.g. SDP payload
    };

    using MessageCallback = std::function<void(const Message&)>;

    SipStack(std::string local_uri);
    ~SipStack();

    /**
     * @brief Generates a SIP INVITE message to initiate a call.
     */
    Message create_invite(const std::string& target_uri, const std::string& sdp_offer);

    /**
     * @brief Generates a 200 OK response to an INVITE.
     */
    Message create_200_ok(const Message& invite_msg, const std::string& sdp_answer);

    /**
     * @brief Parse raw UDP datagrams into SIP Message structs.
     */
    bool parse(const std::string& raw_data, Message& out_msg);

    /**
     * @brief Serialize a Message struct into raw UDP-ready bytes.
     */
    std::string serialize(const Message& msg) const;

private:
    std::string local_uri_;
    uint32_t cseq_ = 1;
    std::string generate_branch_id() const;
};

} // namespace nit::osnova::net
