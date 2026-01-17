#include "../../include/routing/RoutingEngine.h"
#include <algorithm>
#include <iostream>

RoutingTable RoutingEngine::routing_table;

RoutingEngine::RoutingEngine() = default;

void RoutingEngine::loadInterfaces(std::vector<PcapLiveDevice*> interfaces)
{
    this->interfaces = std::move(interfaces);
}

void RoutingEngine::loadRoutingTable(const RoutingTable& table)
{
    routing_table = table;
}

void RoutingEngine::routePacket(pcpp::IPv4Layer* ipLayerPacket, pcpp::IPv4Layer* originalIpLayerPacket)
{
    if (!ipLayerPacket || !originalIpLayerPacket) {
        return;
    }
    auto destination = ipLayerPacket->getDstIPv4Address();
    auto route = routing_table.findRoute(destination);
    if (!route.has_value()) {
        std::cout << "[Routing] No route for " << destination.toString() << std::endl;
        return;
    }

    auto it = std::find_if(interfaces.begin(), interfaces.end(), [&](PcapLiveDevice* device) {
        return device && device->getName() == route->interfaceName;
    });
    if (it == interfaces.end()) {
        std::cout << "[Routing] Interface not found: " << route->interfaceName << std::endl;
        return;
    }

    PcapLiveDevice* outInterface = *it;
    auto* data = originalIpLayerPacket->getData();
    int length = static_cast<int>(originalIpLayerPacket->getDataLen());
    if (length <= 0 || data == nullptr) {
        std::cout << "[Routing] No packet data to forward." << std::endl;
        return;
    }

    if (!outInterface->sendPacket(data, length)) {
        std::cout << "[Routing] Failed to send packet on " << route->interfaceName << std::endl;
        return;
    }

    std::cout << "[Routing] Forwarded packet to " << route->interfaceName << std::endl;
}
