#pragma once
#include "Policy.h"
#include <string>
#include <vector>
#include <memory>
#include "../security_profiles/SecurityProfile.h"

class SecurityProfile;

class SecurityPolicy : public Policy {
public:
    bool allow;
    std::vector<std::shared_ptr<SecurityProfile>> profiles;

    // Use std::string instead of std::pmr::string
    SecurityPolicy(
            std::string network_from_str,
            uint32_t network_from_mask,
            std::string network_to_str,
            uint32_t network_to_mask,
            uint16_t source_port,
            uint16_t destination_port,
            bool allow,
            std::vector<std::shared_ptr<SecurityProfile>> profiles
    ) : Policy(network_from_str, network_from_mask, network_to_str, network_to_mask, source_port, destination_port),
        allow(allow),
        profiles(std::move(profiles))
    {}
    std::vector<std::shared_ptr<SecurityProfile>> evaluate_security_profiles(const pcpp::IPv4Layer& ipLayer);
    bool getAllowPacket() const;
};
