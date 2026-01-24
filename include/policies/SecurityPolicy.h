#pragma once
#include "Policy.h"
#include <string>
#include <vector>
#include <memory>
#include "../security_profiles/SecurityProfile.h"

class SecurityProfile;

/**
 * @brief Policy that applies security profile evaluation.
 */
class SecurityPolicy : public Policy {
public:
    /**
     * @brief Action for packets that match the policy.
     */
    enum class Action {
        Allow,
        Deny
    };

    /** @brief Default allow/deny action for this policy. */
    Action action;
    /** @brief Security profiles evaluated for this policy. */
    std::vector<std::shared_ptr<SecurityProfile>> security_profiles;

    /**
     * @brief Construct a security policy with profiles.
     *
     * @param network_from_str Source network in dotted decimal.
     * @param network_from_mask Source CIDR mask length.
     * @param network_to_str Destination network in dotted decimal.
     * @param network_to_mask Destination CIDR mask length.
     * @param source_port Source port to match (0 for any).
     * @param destination_port Destination port to match (0 for any).
     * @param action Action to take when matched.
     * @param profiles Security profiles to evaluate.
     */
    SecurityPolicy(
        std::string network_from_str,
        uint32_t network_from_mask,
        std::string network_to_str,
        uint32_t network_to_mask,
        uint16_t source_port,
        uint16_t destination_port,
        Action action,
        std::vector<std::shared_ptr<SecurityProfile>> profiles
    ) : Policy(network_from_str, network_from_mask, network_to_str, network_to_mask, source_port, destination_port),
        action(action),
        security_profiles(std::move(profiles))
    {}

    /**
     * @brief Check if the policy allows matched packets.
     *
     * @return True if action is Allow.
     */
    bool allowsPacket() const;
    /**
     * @brief Evaluate security profiles against an IPv4 layer.
     *
     * @param ipLayer IPv4 layer to inspect.
     * @return List of profiles that triggered an alert/block.
     */
    std::vector<std::shared_ptr<SecurityProfile>> evaluate_security_profiles(const pcpp::IPv4Layer& ipLayer) const;
};
