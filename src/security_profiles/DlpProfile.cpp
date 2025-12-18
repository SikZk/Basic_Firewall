#include <regex>
#include "../../include/security_profiles/DlpProfile.h"
#include "../../include/session/sessions/DecryptionSession.h"

DlpProfile::DlpProfile(const std::vector<std::string>& regex_patterns) {
    for (const auto& pattern : regex_patterns) {
        sensitive_data_patterns.emplace_back(pattern, std::regex::icase);
    }
}

Action DlpProfile::scan(const Session& session, pcpp::IPv4Layer /*ipv4_packet*/) {
    const auto* dec_session = dynamic_cast<const DecryptionSession*>(&session);
    if (dec_session == nullptr) return ALLOW;
    std::string data = dec_session->getDecryptedDataAsString();
    for (const auto& re : sensitive_data_patterns) {
        if (std::regex_search(data, re)) {
            return BLOCK;
        }
    }
    return ALLOW;
}
