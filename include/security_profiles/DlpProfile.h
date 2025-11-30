//
// Created by mikolaj on 11/5/25.
//

#ifndef BASIC_FIREWALL_DLP_PROFILE_H
#define BASIC_FIREWALL_DLP_PROFILE_H
#include "SecurityProfile.h"
#include <regex>

class DlpProfile : public SecurityProfile {
    private:
        std::vector<std::regex> sensitive_data_patterns;

    public:
        explicit DlpProfile(const std::vector<std::string>& regex_patterns);
        Action scan(const DecryptionSession& session, pcpp::IPv4Layer ipv4_packet) override;
};

#endif //BASIC_FIREWALL_DLP_PROFILE_H