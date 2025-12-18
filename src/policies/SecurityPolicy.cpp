#include "../../include/policies/SecurityPolicy.h"

std::vector<std::shared_ptr<SecurityProfile>> SecurityPolicy::evaluate_security_profiles(
    pcpp::IPv4Layer& ipv4_packet
) {
    if (!does_match_policy(ipv4_packet)) {
        return {};
    }
    return security_profiles;
}

bool SecurityPolicy::getAllowPacket() { return allow_packet; }
