#include "../../include/routing/RoutingEngine.h"
#include <algorithm>
#include <chrono>
#include <fstream>
#include <iostream>
#include <optional>
#include <sstream>
#include <thread>
#include "pcapplusplus/ArpLayer.h"
#include "pcapplusplus/EthLayer.h"
#include "pcapplusplus/PcapLiveDeviceList.h"
#include "pcapplusplus/PcapLiveDevice.h"
#include "pcapplusplus/PayloadLayer.h"

RoutingTable RoutingEngine::routing_table;

RoutingEngine::RoutingEngine() = default;

namespace {
std::optional<pcpp::MacAddress> readMacFromOsArpCache(const pcpp::IPv4Address& ip,
                                                      const std::string& interfaceName)
{
    std::ifstream arpFile("/proc/net/arp");
    if (!arpFile.is_open()) {
        return std::nullopt;
    }

    std::string line;
    std::getline(arpFile, line);
    while (std::getline(arpFile, line)) {
        std::istringstream lineStream(line);
        std::string ipAddress;
        std::string hwType;
        std::string flags;
        std::string hwAddress;
        std::string mask;
        std::string device;
        if (!(lineStream >> ipAddress >> hwType >> flags >> hwAddress >> mask >> device)) {
            continue;
        }
        if (device != interfaceName) {
            continue;
        }
        if (ipAddress == ip.toString()) {
            return pcpp::MacAddress(hwAddress);
        }
    }
    return std::nullopt;
}

void sendArpProbe(pcpp::PcapLiveDevice* device,
                  const pcpp::IPv4Address& targetIp,
                  const pcpp::MacAddress& sourceMac,
                  const pcpp::IPv4Address& sourceIp)
{
    pcpp::MacAddress broadcastMac("ff:ff:ff:ff:ff:ff");
    pcpp::EthLayer ethLayer(sourceMac, broadcastMac, PCPP_ETHERTYPE_ARP);
    pcpp::ArpLayer arpLayer(pcpp::ARP_REQUEST, sourceMac, broadcastMac, sourceIp, targetIp);

    pcpp::Packet arpPacket(100);
    arpPacket.addLayer(&ethLayer);
    arpPacket.addLayer(&arpLayer);
    arpPacket.computeCalculateFields();
    device->sendPacket(&arpPacket);
}

std::optional<pcpp::MacAddress> resolveNextHopMac(pcpp::PcapLiveDevice* device,
                                                  const pcpp::IPv4Address& nextHop)
{
    if (!device) {
        return std::nullopt;
    }
    auto interfaceName = device->getName();
    auto cached = readMacFromOsArpCache(nextHop, interfaceName);
    if (cached.has_value()) {
        return cached;
    }

    auto sourceMac = device->getMacAddress();
    auto sourceIp = device->getIPv4Address();
    if (!sourceMac.isValid() || !sourceIp.isValid()) {
        return std::nullopt;
    }

    sendArpProbe(device, nextHop, sourceMac, sourceIp);
    for (int attempt = 0; attempt < 5; ++attempt) {
        std::this_thread::sleep_for(std::chrono::milliseconds(50));
        cached = readMacFromOsArpCache(nextHop, interfaceName);
        if (cached.has_value()) {
            return cached;
        }
    }
    return std::nullopt;
}
} // namespace

void RoutingEngine::loadInterfaces(std::vector<pcpp::PcapLiveDevice*> interfaces)
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
    (void)originalIpLayerPacket;
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
    pcpp::IPv4Address nextHop = route->gateway;
    if (nextHop == pcpp::IPv4Address("0.0.0.0")) {
        nextHop = destination;
    }

    auto nextHopMac = resolveNextHopMac(outInterface, nextHop);
    if (!nextHopMac.has_value()) {
        std::cout << "[Routing] Unable to resolve MAC for " << nextHop.toString()
                  << " via " << route->interfaceName << std::endl;
        return;
    }

    auto sourceMac = outInterface->getMacAddress();
    if (!sourceMac.isValid()) {
        std::cout << "[Routing] Unable to read MAC for " << route->interfaceName << std::endl;
        return;
    }

    auto* data = ipLayerPacket->getData();
    int length = static_cast<int>(ipLayerPacket->getDataLen());
    if (length <= 0 || data == nullptr) {
        std::cout << "[Routing] No packet data to forward." << std::endl;
        return;
    }

    pcpp::EthLayer ethLayer(sourceMac, nextHopMac.value(), PCPP_ETHERTYPE_IP);
    pcpp::PayloadLayer payloadLayer(data, length, true);
    pcpp::Packet outPacket(length + 32);
    outPacket.addLayer(&ethLayer);
    outPacket.addLayer(&payloadLayer);
    outPacket.computeCalculateFields();

    if (!outInterface->sendPacket(&outPacket)) {
        std::cout << "[Routing] Failed to send packet on " << route->interfaceName << std::endl;
        return;
    }

    std::cout << "[Routing] Forwarded packet to " << route->interfaceName << std::endl;
}
