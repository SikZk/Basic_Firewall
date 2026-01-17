//
// Created by mikolaj on 11/5/25.
//

#ifndef BASIC_FIREWALL_SECURITY_POLICY_H
#define BASIC_FIREWALL_SECURITY_POLICY_H

#include <pcapplusplus/IPv4Layer.h>
#include <vector>
#include <string>
#include <memory_resource>
#include "Policy.h"

#include "../security_profiles/SecurityProfile.h"

class SecurityPolicy : public Policy {
    private:
        bool allow_packet;
        std::vector<std::shared_ptr<SecurityProfile>> security_profiles;
    public:
        SecurityPolicy(
            std::pmr::string network_from_str,
            std::uint32_t    from_mask,
            std::pmr::string network_to_str,
            std::uint32_t    to_mask,
            std::uint16_t    src_port,
            std::uint16_t    dest_port,
            bool             allow_packet,
            std::vector<std::shared_ptr<SecurityProfile>> security_profiles
        )
        : Policy(
            std::move(network_from_str),
            from_mask,
            std::move(network_to_str),
            to_mask,
            src_port,
            dest_port
        ),
          allow_packet(allow_packet),
          security_profiles(std::move(security_profiles))
        {};

        std::vector<std::shared_ptr<SecurityProfile>> evaluate_security_profiles(const pcpp::IPv4Layer& ipLayer);
        bool getAllowPacket();
};

#endif //BASIC_FIREWALL_SECURITY_POLICY_H