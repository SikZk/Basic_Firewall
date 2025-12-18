#include "../../include/policies/NatPolicy.h"

NatState NatPolicy::nat_state(1024, 65535);

void NatPolicy::configureNatState(uint16_t port_start, uint16_t port_end) {
    nat_state = NatState(port_start, port_end);
}

pcpp::IPv4Layer NatPolicy::applyNat(pcpp::IPv4Layer* ipLayer) {
    return *ipLayer;
}
