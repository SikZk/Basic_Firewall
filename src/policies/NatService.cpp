#include "../../include/policies/NatService.h"
#include <iostream>

pcpp::IPv4Layer* NatService::applyNat(NatSession session, pcpp::IPv4Layer* ipLayerPacket)
{
    (void)session;
    std::cout << "[NAT] Skipping translation (no-op)." << std::endl;
    return ipLayerPacket;
}
