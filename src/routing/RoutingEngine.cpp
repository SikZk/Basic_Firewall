#include "../../include/routing/RoutingEngine.h"
#include <algorithm>
#include <chrono>
#include <fstream>
#include <iostream>
#include <optional>
#include <sstream>
#include <thread>
#include <unordered_map>
#include "pcapplusplus/ArpLayer.h"
#include "pcapplusplus/EthLayer.h"
#include "pcapplusplus/MacAddress.h"
#include "pcapplusplus/PcapLiveDeviceList.h"
#include "pcapplusplus/PcapLiveDevice.h"

namespace {
struct ArpCacheState {
    std::unordered_map<std::string, pcpp::MacAddress> entries;
    std::chrono::steady_clock::time_point lastRefresh = std::chrono::steady_clock::time_point::min();
};

ArpCacheState& getArpCacheState()
{
    static ArpCacheState state;
    return state;
}

void refreshArpCache()
{
    auto& state = getArpCacheState();
    std::ifstream arpFile("/proc/net/arp");
    if (!arpFile.is_open()) {
        return;
    }
    std::unordered_map<std::string, pcpp::MacAddress> nextEntries;
    std::string line;
    std::getline(arpFile, line);
    while (std::getline(arpFile, line)) {
        std::istringstream stream(line);
        std::string ipAddress;
        std::string hwType;
        std::string flags;
        std::string hwAddress;
        std::string mask;
        std::string device;
        if (!(stream >> ipAddress >> hwType >> flags >> hwAddress >> mask >> device)) {
            continue;
        }
        nextEntries.emplace(ipAddress, pcpp::MacAddress(hwAddress));
    }
    state.entries = std::move(nextEntries);
    state.lastRefresh = std::chrono::steady_clock::now();
}

std::optional<pcpp::MacAddress> lookupArpCache(const pcpp::IPv4Address& ip)
{
    auto& state = getArpCacheState();
    auto now = std::chrono::steady_clock::now();
    if (now - state.lastRefresh > std::chrono::milliseconds(250)) {
        refreshArpCache();
    }
    auto it = state.entries.find(ip.toString());
    if (it == state.entries.end()) {
        return std::nullopt;
    }
    return it->second;
}

bool sendArpRequest(pcpp::PcapLiveDevice* device, const pcpp::IPv4Address& targetIp)
{
    if (!device) {
        return false;
    }
    pcpp::MacAddress sourceMac = device->getMacAddress();
    pcpp::IPv4Address sourceIp = device->getIPv4Address();
    pcpp::MacAddress broadcastMac("ff:ff:ff:ff:ff:ff");

    pcpp::Packet arpRequest(42);
    auto* ethLayer = new pcpp::EthLayer(sourceMac, broadcastMac, PCPP_ETHERTYPE_ARP);
    auto* arpLayer = new pcpp::ArpLayer(pcpp::ARP_REQUEST, sourceMac, broadcastMac, sourceIp, targetIp);
    arpRequest.addLayer(ethLayer);
    arpRequest.addLayer(arpLayer);
    arpRequest.computeCalculateFields();

    return device->sendPacket(&arpRequest);
}
} // namespace

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
    pcpp::Packet packetCopy(packet);
    auto* ethLayer = packetCopy.getLayerOfType<pcpp::EthLayer>();
    if (!ethLayer) {
        std::cout << "[Routing] Missing Ethernet layer." << std::endl;
        return;
    }

    auto gateway = route->gateway;
    pcpp::IPv4Address nextHop = gateway == pcpp::IPv4Address("0.0.0.0") ? destination : gateway;
    auto nextHopMac = lookupArpCache(nextHop);
    if (!nextHopMac.has_value()) {
        sendArpRequest(outInterface, nextHop);
        for (int attempt = 0; attempt < 3 && !nextHopMac.has_value(); ++attempt) {
            std::this_thread::sleep_for(std::chrono::milliseconds(20));
            nextHopMac = lookupArpCache(nextHop);
        }
    }
    if (!nextHopMac.has_value()) {
        std::cout << "[Routing] Failed to resolve MAC for " << nextHop.toString() << std::endl;
        return;
    }

    ethLayer->setSourceMac(outInterface->getMacAddress());
    ethLayer->setDestMac(*nextHopMac);
    packetCopy.computeCalculateFields();

    if (!outInterface->sendPacket(&packetCopy)) {
        std::cout << "[Routing] Failed to send packet on " << route->interfaceName << std::endl;
        return;
    }

    std::cout << "[Routing] Forwarded packet to " << route->interfaceName << std::endl;
}
