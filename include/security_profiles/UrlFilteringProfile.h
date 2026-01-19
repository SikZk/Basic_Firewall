//
// Created by mikolaj on 11/5/25.
//public

#ifndef BASIC_FIREWALL_URL_FILTERING_PROFILE_H
#define BASIC_FIREWALL_URL_FILTERING_PROFILE_H
#include "SecurityProfile.h"
#include <unordered_set>
#include <vector>

class UrlFilteringProfile : public SecurityProfile {
    private:
        std::unordered_set<std::string> blocked_domains;

    public:
        std::string name;
        explicit UrlFilteringProfile(std::string name, const std::vector<std::string>& domains_to_block);
        Action scan(Session* session, const pcpp::Packet& packet) override;
        Action scan(const DecryptionSession& session, const pcpp::Packet& packet) override;
};

#endif //BASIC_FIREWALL_URL_FILTERING_PROFILE_H
