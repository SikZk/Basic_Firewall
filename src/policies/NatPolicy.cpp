#include "../../include/policies/NatPolicy.h"
#include <iostream>

NatState NatPolicy::nat_state(10000, 20000);

void NatPolicy::configureNatState(uint16_t port_start, uint16_t port_end)
{
    nat_state = NatState(port_start, port_end);
}

NatState& NatPolicy::getNatState()
{
    return nat_state;
}

pcpp::IPv4Layer NatPolicy::applyNat(pcpp::IPv4Layer* ipLayer)
{
    std::cout << "[NAT] No-op NAT applied." << std::endl;
    return *ipLayer;
}

NatType NatPolicy::getNatType() const
{
    return nat_type;
}

pcpp::IPv4Address NatPolicy::getTranslatedSourceIp() const
{
    return translated_source_ip;
}

pcpp::IPv4Address NatPolicy::getTranslatedDestinationIp() const
{
    return translated_destination_ip;
}
