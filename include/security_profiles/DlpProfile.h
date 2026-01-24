#ifndef BASIC_FIREWALL_DLP_PROFILE_H
#define BASIC_FIREWALL_DLP_PROFILE_H
#include "SecurityProfile.h"
#include <regex>
#include <vector>

class DlpProfile : public SecurityProfile {
private:
    std::vector<std::regex> sensitive_data_patterns;

public:
    explicit DlpProfile(const std::vector<std::string>& regex_patterns);
    Action scan(Session* session, const pcpp::IPv4Layer& packet) override;
    Action scan(const DecryptionSession& session, const pcpp::IPv4Layer& ipv4_packet) override;
};

#endif
