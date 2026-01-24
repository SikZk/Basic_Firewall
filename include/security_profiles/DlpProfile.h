#ifndef BASIC_FIREWALL_DLP_PROFILE_H
#define BASIC_FIREWALL_DLP_PROFILE_H
#include "SecurityProfile.h"
#include <regex>
#include <vector>

/**
 * @brief Data loss prevention profile that matches sensitive patterns.
 */
class DlpProfile : public SecurityProfile {
private:
    std::vector<std::regex> sensitive_data_patterns;

public:
    /**
     * @brief Construct a DLP profile with regex patterns.
     *
     * @param regex_patterns Patterns for detecting sensitive data.
     */
    explicit DlpProfile(const std::vector<std::string>& regex_patterns);
    /**
     * @brief Scan a plaintext packet for sensitive data.
     *
     * @param session Active session for the flow.
     * @param packet IPv4 packet layer to inspect.
     * @return Action indicating allow/block/alert decision.
     */
    Action scan(Session* session, const pcpp::IPv4Layer& packet) override;
    /**
     * @brief Scan a decrypted packet for sensitive data.
     *
     * @param session Decryption session with decrypted payload.
     * @param ipv4_packet IPv4 packet layer to inspect.
     * @return Action indicating allow/block/alert decision.
     */
    Action scan(const DecryptionSession& session, const pcpp::IPv4Layer& ipv4_packet) override;
};

#endif
