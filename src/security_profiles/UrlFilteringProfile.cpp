#include "../../include/security_profiles/UrlFilteringProfile.h"
#include "../../include/session/sessions/DecryptionSession.h"

UrlFilteringProfile::UrlFilteringProfile(const std::vector<std::string>& domains_to_block)
    : blocked_domains(domains_to_block.begin(), domains_to_block.end()) {}

Action UrlFilteringProfile::scan(const Session& session, pcpp::IPv4Layer /*ipv4_packet*/) {
    const auto* dec_session = dynamic_cast<const DecryptionSession*>(&session);
    if (dec_session == nullptr) return ALLOW;
    std::string payload = dec_session->getDecryptedDataAsString();
    for (const auto& domain : blocked_domains) {
        if (payload.find(domain) != std::string::npos) {
            return BLOCK;
        }
    }
    return ALLOW;
}
