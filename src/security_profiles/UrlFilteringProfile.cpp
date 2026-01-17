#include "../../include/security_profiles/UrlFilteringProfile.h"
#include <iostream>

UrlFilteringProfile::UrlFilteringProfile(const std::vector<std::string>& domains_to_block)
    : blocked_domains(domains_to_block.begin(), domains_to_block.end())
{
}

Action UrlFilteringProfile::scan(const DecryptionSession&, pcpp::IPv4Layer)
{
    std::cout << "[UrlFiltering] No-op scan." << std::endl;
    return ALLOW;
}

Action UrlFilteringProfile::scan(Session*, const pcpp::IPv4Layer&)
{
    std::cout << "[UrlFiltering] No-op scan (plaintext)." << std::endl;
    return ALLOW;
}
