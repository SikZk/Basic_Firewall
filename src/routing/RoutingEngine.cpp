#include "../../include/routing/RoutingEngine.h"
#include <algorithm>
#include <iostream>
#include "pcapplusplus/EthLayer.h"
#include "pcapplusplus/MacAddress.h"
#include "pcapplusplus/PcapLiveDeviceList.h"
#include "pcapplusplus/PcapLiveDevice.h"

RoutingTable RoutingEngine::routing_table;

RoutingEngine::RoutingEngine() = default;

void RoutingEngine::loadInterfaces(std::vector<pcpp::PcapLiveDevice*> interfaces)
{
    this->interfaces = std::move(interfaces);
}

void RoutingEngine::loadRoutingTable(const RoutingTable& table)
{
    routing_table = table;
}

void RoutingEngine::routePacket(pcpp::Packet& packet, pcpp::IPv4Layer* ipLayerPacket)
{
    if (!ipLayerPacket) {
        return;
    }
    auto destination = ipLayerPacket->getDstIPv4Address();
    auto route = routing_table.findRoute(destination);
    if (!route.has_value()) {
        std::cout << "[Routing] No route for " << destination.toString() << std::endl;
        return;
    }

    auto it = std::find_if(interfaces.begin(), interfaces.end(), [&](pcpp::PcapLiveDevice* device) {
        return device && device->getName() == route->interfaceName;
    });
    if (it == interfaces.end()) {
        std::cout << "[Routing] Interface not found: " << route->interfaceName << std::endl;
        return;
    }

    pcpp::PcapLiveDevice* outInterface = *it;
    auto* ethLayer = packet.getLayerOfType<pcpp::EthLayer>();
    if (!ethLayer) {
        std::cout << "[Routing] Missing Ethernet layer." << std::endl;
        return;
    }

    auto gateway = route->gateway;
    pcpp::IPv4Address nextHop = gateway == pcpp::IPv4Address("0.0.0.0") ? destination : gateway;
    pcpp::MacAddress nextHopMac = outInterface->getMacAddressOfIPv4Address(nextHop);
    if (!nextHopMac.isValid()) {
        std::cout << "[Routing] Failed to resolve MAC for " << nextHop.toString() << std::endl;
        return;
    }

    ethLayer->setSourceMac(outInterface->getMacAddress());
    ethLayer->setDestMac(nextHopMac);
    packet.computeCalculateFields();

    if (!outInterface->sendPacket(packet)) {
        std::cout << "[Routing] Failed to send packet on " << route->interfaceName << std::endl;
        return;
    }

    std::cout << "[Routing] Forwarded packet to " << route->interfaceName << std::endl;
}
