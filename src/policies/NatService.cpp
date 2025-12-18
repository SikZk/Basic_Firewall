#include "../../include/policies/NatService.h"

pcpp::IPv4Layer* NatService::applyNat(NatSession session, pcpp::IPv4Layer* ipLayerPacket) {
    if (session.is_source_nat) {
        ipLayerPacket->setSrcIPv4Address(session.nat_ip);
    } else {
        ipLayerPacket->setDstIPv4Address(session.nat_ip);
    }
    return ipLayerPacket;
}
