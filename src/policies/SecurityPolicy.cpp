#include "../../include/policies/SecurityPolicy.h"
#include <iostream>

std::vector<std::shared_ptr<SecurityProfile>> SecurityPolicy::evaluate_security_profiles(const pcpp::IPv4Layer& ipLayer)
{
    std::cout << "[SecurityPolicy] Evaluating security profiles for "
              << ipLayer.getSrcIPv4Address().toString() << " -> "
              << ipLayer.getDstIPv4Address().toString() << std::endl;
    return security_profiles;
}

bool SecurityPolicy::getAllowPacket() const
{
    return allow;
}
