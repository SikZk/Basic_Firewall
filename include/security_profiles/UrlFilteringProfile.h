#ifndef BASIC_FIREWALL_URL_FILTERING_PROFILE_H
#define BASIC_FIREWALL_URL_FILTERING_PROFILE_H
#include "SecurityProfile.h"
#include <unordered_set>
#include <vector>
#include <string>

/**
 * @brief Security profile that blocks traffic to specific domains.
 */
class UrlFilteringProfile : public SecurityProfile {
private:
    std::unordered_set<std::string> blocked_domains;
    friend class SecurityProfilesTest;
    /**
     * @brief Determine if a host should be blocked.
     *
     * @param host Hostname to evaluate.
     * @return True when the host matches blocked domains.
     */
    bool shouldBlockHost(const std::string& host) const;
    /**
     * @brief Normalize a host for comparison.
     *
     * @param host Hostname to normalize.
     * @return Lowercase host without trailing dots.
     */
    static std::string normalizeHost(std::string host);
    /**
     * @brief Extract the Host header from HTTP payload.
     *
     * @param payload Raw HTTP payload string.
     * @return Extracted host value or empty string.
     */
    static std::string extractHostFromHttp(const std::string& payload);

public:
    /**
     * @brief Construct with a list of domains to block.
     *
     * @param domains_to_block Domain list to add to the block set.
     */
    explicit UrlFilteringProfile(const std::vector<std::string>& domains_to_block);
    /**
     * @brief Scan plaintext traffic for blocked domains.
     *
     * @param session Active session for the flow.
     * @param packet IPv4 packet layer to inspect.
     * @return Action indicating allow/block/alert decision.
     */
    Action scan(Session* session, const pcpp::IPv4Layer& packet) override;
    /**
     * @brief Scan decrypted traffic for blocked domains.
     *
     * @param session Decryption session with decrypted payload.
     * @param ipv4_packet IPv4 packet layer to inspect.
     * @return Action indicating allow/block/alert decision.
     */
    Action scan(const DecryptionSession& session, const pcpp::IPv4Layer& ipv4_packet) override;
};

#endif
