#include "sip_stack.h"
#include "../crypto/secure_random.h"
#include <sstream>

namespace nit::osnova::net {

SipStack::SipStack(std::string local_uri) : local_uri_(std::move(local_uri)) {}
SipStack::~SipStack() = default;

std::string SipStack::generate_branch_id() const {
    std::vector<uint8_t> rand(8);
    crypto::osnova::SecureRandom::get_instance().generate(rand);
    std::stringstream ss;
    ss << "z9hG4bK-";
    for (uint8_t b : rand) {
        ss << std::hex << (int)b;
    }
    return ss.str();
}

SipStack::Message SipStack::create_invite(const std::string& target_uri, const std::string& sdp_offer) {
    Message msg;
    msg.method = "INVITE";
    msg.uri = target_uri;
    msg.version = "SIP/2.0";
    
    msg.headers["Via"] = "SIP/2.0/UDP " + local_uri_ + ";branch=" + generate_branch_id();
    msg.headers["From"] = "<" + local_uri_ + ">;tag=" + generate_branch_id();
    msg.headers["To"] = "<" + target_uri + ">";
    msg.headers["Call-ID"] = generate_branch_id() + "@" + local_uri_;
    msg.headers["CSeq"] = std::to_string(cseq_++) + " INVITE";
    msg.headers["Contact"] = "<" + local_uri_ + ">";
    msg.headers["Max-Forwards"] = "70";
    msg.headers["Content-Type"] = "application/sdp";
    msg.headers["Content-Length"] = std::to_string(sdp_offer.size());
    
    msg.body = sdp_offer;
    return msg;
}

SipStack::Message SipStack::create_200_ok(const Message& invite_msg, const std::string& sdp_answer) {
    Message msg;
    msg.method = "SIP/2.0";
    msg.uri = "200";
    msg.version = "OK"; // Abusing struct fields for response line

    auto it_via = invite_msg.headers.find("Via");
    if (it_via != invite_msg.headers.end()) msg.headers["Via"] = it_via->second;

    auto it_from = invite_msg.headers.find("From");
    if (it_from != invite_msg.headers.end()) msg.headers["From"] = it_from->second;

    auto it_to = invite_msg.headers.find("To");
    if (it_to != invite_msg.headers.end()) msg.headers["To"] = it_to->second + ";tag=" + generate_branch_id();

    auto it_call = invite_msg.headers.find("Call-ID");
    if (it_call != invite_msg.headers.end()) msg.headers["Call-ID"] = it_call->second;

    auto it_cseq = invite_msg.headers.find("CSeq");
    if (it_cseq != invite_msg.headers.end()) msg.headers["CSeq"] = it_cseq->second;

    msg.headers["Contact"] = "<" + local_uri_ + ">";
    msg.headers["Content-Type"] = "application/sdp";
    msg.headers["Content-Length"] = std::to_string(sdp_answer.size());
    
    msg.body = sdp_answer;
    return msg;
}

bool SipStack::parse(const std::string& raw_data, Message& out_msg) {
    if (raw_data.empty()) return false;

    // Regex-based SIP parser
    size_t body_pos = raw_data.find("\r\n\r\n");
    if (body_pos == std::string::npos) return false;

    std::string headers_part = raw_data.substr(0, body_pos);
    out_msg.body = raw_data.substr(body_pos + 4);

    std::stringstream ss(headers_part);
    std::string line;
    if (std::getline(ss, line)) {
        if (!line.empty() && line.back() == '\r') line.pop_back();
        // Assuming Request-Line: METHOD URI VERSION
        std::stringstream line_ss(line);
        line_ss >> out_msg.method >> out_msg.uri >> out_msg.version;
    }

    while (std::getline(ss, line)) {
        if (!line.empty() && line.back() == '\r') line.pop_back();
        size_t colon = line.find(':');
        if (colon != std::string::npos) {
            std::string key = line.substr(0, colon);
            std::string val = line.substr(colon + 1);
            if (!val.empty() && val[0] == ' ') val = val.substr(1);
            out_msg.headers[key] = val;
        }
    }
    
    return true;
}

std::string SipStack::serialize(const Message& msg) const {
    std::stringstream ss;
    ss << msg.method << " " << msg.uri << " " << msg.version << "\r\n";
    for (const auto& kv : msg.headers) {
        ss << kv.first << ": " << kv.second << "\r\n";
    }
    ss << "\r\n" << msg.body;
    return ss.str();
}

} // namespace nit::osnova::net
