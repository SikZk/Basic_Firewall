//
// Created by mikolaj on 11/5/25.
//public

#ifndef BASIC_FIREWALL_URL_FILTERING_PROFILE_H
#define BASIC_FIREWALL_URL_FILTERING_PROFILE_H
#include "SecurityProfile.h"

class UrlFilteringProfile : public SecurityProfile {
    private:
        std::unordered_set<std::string> blocked_domains;

    public:
        explicit UrlFilteringProfile(const std::vector<std::string>& domains_to_block);
        Action scan(const DecryptionSession& session, pcpp::IPv4Layer ipv4_packet) override;
};

#endif //BASIC_FIREWALL_URL_FILTERING_PROFILE_H