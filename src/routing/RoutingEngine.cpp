#include "../../include/routing/RoutingEngine.h"

RoutingTable RoutingEngine::routing_table{};

RoutingEngine::RoutingEngine() = default;

void RoutingEngine::routePacket(pcpp::IPv4Layer* ipLayerPacket, pcpp::IPv4Layer* /*originalIpLayerPacket*/) {
    if (ipLayerPacket == nullptr) return;
    auto route = routing_table.findRoute(ipLayerPacket->getDstIPv4Address());
    if (!route.has_value()) return;
    (void)route;
}

void RoutingEngine::loadInterfaces(std::vector<pcpp::PcapLiveDevice*> interfaces_param) {
    interfaces = std::move(interfaces_param);
}
