#include "../../include/security_profiles/DlpProfile.h"
#include <iostream>

DlpProfile::DlpProfile(const std::vector<std::string>& regex_patterns)
{
    sensitive_data_patterns.reserve(regex_patterns.size());
    for (const auto& pattern : regex_patterns) {
        sensitive_data_patterns.emplace_back(pattern);
    }
}

Action DlpProfile::scan(Session*, const pcpp::IPv4Layer&)
{
    std::cout << "[DLP] No-op scan." << std::endl;
    return ALLOW;
}

Action DlpProfile::scan(const DecryptionSession&, pcpp::IPv4Layer)
{
    std::cout << "[DLP] No-op scan (decrypted)." << std::endl;
    return ALLOW;
}
