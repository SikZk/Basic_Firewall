#include "../../include/routing/RoutingEngine.h"
#include <algorithm>
#include <array>
#include <cstdio>
#include <cstring>
#include <iostream>
#include <net/if.h>
#include <netinet/ether.h>
#include <netinet/in.h>
#include <netinet/if_ether.h>
#include <optional>
#include <vector>
#include <sys/ioctl.h>
#include <sys/socket.h>
#include <unistd.h>
#include "pcapplusplus/MacAddress.h"
#include "pcapplusplus/PcapLiveDeviceList.h"
#include "pcapplusplus/PcapLiveDevice.h"

RoutingTable RoutingEngine::routing_table;

RoutingEngine::RoutingEngine() = default;

void RoutingEngine::loadInterfaces(std::vector<pcpp::PcapLiveDevice*> interfaces)
{
    this->interfaces = std::move(interfaces);
}

namespace {
void primeArpCache(const std::string& interfaceName, const pcpp::IPv4Address& nextHop)
{
    const int sock = ::socket(AF_INET, SOCK_DGRAM, 0);
    if (sock < 0) {
        return;
    }

    if (!interfaceName.empty()) {
        if (::setsockopt(sock, SOL_SOCKET, SO_BINDTODEVICE, interfaceName.c_str(),
                         static_cast<socklen_t>(interfaceName.size() + 1)) != 0) {
            // Best-effort; continue without binding if it fails.
        }
    }

    sockaddr_in addr{};
    addr.sin_family = AF_INET;
    addr.sin_port = htons(9);
    addr.sin_addr.s_addr = htonl(nextHop.toInt());

    const char payload[1] = {0};
    ::sendto(sock, payload, sizeof(payload), 0,
             reinterpret_cast<sockaddr*>(&addr), sizeof(addr));
    ::close(sock);
}
} // namespace

std::optional<pcpp::MacAddress> RoutingEngine::resolveMacAddress(pcpp::PcapLiveDevice* device,
                                                                 const pcpp::IPv4Address& nextHop)
{
    if (!device) {
        return std::nullopt;
    }
    auto cacheIt = arpCache.find(nextHop.toInt());
    if (cacheIt != arpCache.end()) {
        return cacheIt->second;
    }

    const int sock = ::socket(AF_INET, SOCK_DGRAM, 0);
    if (sock < 0) {
        std::cout << "[Routing] Failed to open ARP socket." << std::endl;
        return std::nullopt;
    }

    struct arpreq req {};
    struct sockaddr_in* sin = reinterpret_cast<struct sockaddr_in*>(&req.arp_pa);
    sin->sin_family = AF_INET;
    sin->sin_addr.s_addr = htonl(nextHop.toInt());
    std::snprintf(req.arp_dev, sizeof(req.arp_dev), "%s", device->getName().c_str());

    if (::ioctl(sock, SIOCGARP, &req) != 0) {
        ::close(sock);
        std::cout << "[Routing] ARP cache miss for " << nextHop.toString()
                  << " on " << device->getName() << " - probing via OS." << std::endl;
        primeArpCache(device->getName(), nextHop);

        const int retrySock = ::socket(AF_INET, SOCK_DGRAM, 0);
        if (retrySock < 0) {
            return std::nullopt;
        }
        struct arpreq retryReq {};
        struct sockaddr_in* retrySin = reinterpret_cast<struct sockaddr_in*>(&retryReq.arp_pa);
        retrySin->sin_family = AF_INET;
        retrySin->sin_addr.s_addr = htonl(nextHop.toInt());
        std::snprintf(retryReq.arp_dev, sizeof(retryReq.arp_dev), "%s",
                      device->getName().c_str());
        if (::ioctl(retrySock, SIOCGARP, &retryReq) != 0) {
            ::close(retrySock);
            std::cout << "[Routing] ARP cache still empty for " << nextHop.toString()
                      << " on " << device->getName() << std::endl;
            return std::nullopt;
        }
        ::close(retrySock);
        req = retryReq;
    }

    ::close(sock);
    std::array<uint8_t, 6> macBytes{};
    std::memcpy(macBytes.data(), req.arp_ha.sa_data, macBytes.size());
    pcpp::MacAddress mac(macBytes.data());
    arpCache[nextHop.toInt()] = mac;
    return mac;
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

    auto it = std::find_if(interfaces.begin(), interfaces.end(), [&](pcpp::PcapLiveDevice* device) {
        return device && device->getName() == route->interfaceName;
    });
    if (it == interfaces.end()) {
        std::cout << "[Routing] Interface not found: " << route->interfaceName << std::endl;
        return;
    }

    pcpp::PcapLiveDevice* outInterface = *it;
    auto* data = originalIpLayerPacket->getData();
    int length = static_cast<int>(originalIpLayerPacket->getDataLen());
    if (length <= 0 || data == nullptr) {
        std::cout << "[Routing] No packet data to forward." << std::endl;
        return;
    }

    pcpp::IPv4Address nextHop = route->gateway;
    if (nextHop == pcpp::IPv4Address("0.0.0.0")) {
        nextHop = destination;
    }
    std::optional<pcpp::MacAddress> nextHopMac = resolveMacAddress(outInterface, nextHop);
    if (!nextHopMac.has_value()) {
        std::cout << "[Routing] Unable to resolve MAC for " << nextHop.toString() << std::endl;
        return;
    }

    pcpp::MacAddress sourceMac = outInterface->getMacAddress();
    if (!sourceMac.isValid()) {
        std::cout << "[Routing] Unable to resolve source MAC for " << route->interfaceName << std::endl;
        return;
    }

    std::vector<uint8_t> frame(sizeof(ether_header) + static_cast<size_t>(length));
    auto* eth = reinterpret_cast<ether_header*>(frame.data());
    std::memcpy(eth->ether_dhost, nextHopMac->getRawData(), ETH_ALEN);
    std::memcpy(eth->ether_shost, sourceMac.getRawData(), ETH_ALEN);
    eth->ether_type = htons(ETHERTYPE_IP);
    std::memcpy(frame.data() + sizeof(ether_header), data, static_cast<size_t>(length));

    if (!outInterface->sendPacket(frame.data(), static_cast<int>(frame.size()))) {
        std::cout << "[Routing] Failed to send packet on " << route->interfaceName << std::endl;
        return;
    }

    std::cout << "[Routing] Forwarded packet to " << route->interfaceName << std::endl;
}
