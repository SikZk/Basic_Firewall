#ifndef BASIC_FIREWALL_URL_FILTERING_PROFILE_H
#define BASIC_FIREWALL_URL_FILTERING_PROFILE_H
#include "SecurityProfile.h"
#include <unordered_set>
#include <vector>
#include <string>

class UrlFilteringProfile : public SecurityProfile {
private:
    std::unordered_set<std::string> blocked_domains;
    bool shouldBlockHost(const std::string& host) const;
    static std::string normalizeHost(std::string host);
    static std::string extractHostFromHttp(const std::string& payload);

public:
    explicit UrlFilteringProfile(const std::vector<std::string>& domains_to_block);
    Action scan(Session* session, const pcpp::IPv4Layer& packet) override;
    Action scan(const DecryptionSession& session, const pcpp::IPv4Layer& ipv4_packet) override;
};

#endif
