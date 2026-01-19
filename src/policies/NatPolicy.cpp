#include "../../include/policies/NatPolicy.h"
#include <iostream>

// Initialize static member
NatState NatPolicy::nat_state(10000, 20000);

void NatPolicy::configureNatState(uint16_t port_start, uint16_t port_end)
{
    // Re-initialize the static state with new port range
    nat_state = NatState(port_start, port_end);
}

pcpp::IPv4Layer NatPolicy::applyNat(pcpp::IPv4Layer* ipLayer)
{
    // The actual packet modification happens in NatService.
    // This function remains as a placeholder or helper if you wish to move logic here later.
    std::cout << "[NAT] Policy matched." << std::endl;
    return *ipLayer;
}