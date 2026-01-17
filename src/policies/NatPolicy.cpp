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
