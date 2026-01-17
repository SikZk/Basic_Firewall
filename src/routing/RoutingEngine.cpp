#include "../../include/routing/RoutingEngine.h"
#include <algorithm>
#include <array>
#include <chrono>
#include <cstdio>
#include <cstring>
#include <fstream>
#include <iostream>
#include <optional>
#include <sstream>
#include <thread>
#include <vector>
#include <arpa/inet.h>
#include <net/if.h>
#include <sys/ioctl.h>
#include <sys/socket.h>
#include <unistd.h>
#include "pcapplusplus/PcapLiveDeviceList.h"
#include "pcapplusplus/PcapLiveDevice.h"

RoutingTable RoutingEngine::routing_table;

namespace {
constexpr size_t kEthernetHeaderSize = 14;
constexpr uint16_t kEtherTypeIPv4 = 0x0800;

std::optional<std::array<uint8_t, 6>> parseMacAddress(const std::string& mac) {
    std::array<uint8_t, 6> bytes{};
    unsigned int values[6] = {};
    if (std::sscanf(mac.c_str(), "%x:%x:%x:%x:%x:%x",
                    &values[0], &values[1], &values[2],
                    &values[3], &values[4], &values[5]) != 6) {
        return std::nullopt;
    }
    for (size_t i = 0; i < 6; ++i) {
        bytes[i] = static_cast<uint8_t>(values[i]);
    }
    return bytes;
}

std::optional<std::array<uint8_t, 6>> getInterfaceMacAddress(const std::string& iface) {
    int fd = socket(AF_INET, SOCK_DGRAM, 0);
    if (fd < 0) {
        return std::nullopt;
    }

    struct ifreq ifr {};
    std::snprintf(ifr.ifr_name, sizeof(ifr.ifr_name), "%s", iface.c_str());
    if (ioctl(fd, SIOCGIFHWADDR, &ifr) < 0) {
        close(fd);
        return std::nullopt;
    }
    close(fd);

    std::array<uint8_t, 6> mac{};
    std::memcpy(mac.data(), ifr.ifr_hwaddr.sa_data, mac.size());
    return mac;
}

std::optional<std::array<uint8_t, 6>> lookupArpCache(const std::string& ip) {
    std::ifstream arpFile("/proc/net/arp");
    if (!arpFile.is_open()) {
        return std::nullopt;
    }

    std::string line;
    std::getline(arpFile, line);
    while (std::getline(arpFile, line)) {
        std::istringstream iss(line);
        std::string ipAddress;
        std::string hwType;
        std::string flags;
        std::string macAddress;
        std::string mask;
        std::string device;

        if (!(iss >> ipAddress >> hwType >> flags >> macAddress >> mask >> device)) {
            continue;
        }

        if (ipAddress == ip) {
            return parseMacAddress(macAddress);
        }
    }

    return std::nullopt;
}

void triggerArpResolution(const std::string& iface, const std::string& ip) {
    int sock = socket(AF_INET, SOCK_DGRAM, 0);
    if (sock < 0) {
        return;
    }

    if (setsockopt(sock, SOL_SOCKET, SO_BINDTODEVICE, iface.c_str(), iface.size() + 1) < 0) {
        close(sock);
        return;
    }

    sockaddr_in addr {};
    addr.sin_family = AF_INET;
    addr.sin_port = htons(9);
    if (inet_pton(AF_INET, ip.c_str(), &addr.sin_addr) != 1) {
        close(sock);
        return;
    }

    std::array<uint8_t, 1> payload {0};
    sendto(sock, payload.data(), payload.size(), 0, reinterpret_cast<sockaddr*>(&addr), sizeof(addr));
    close(sock);
}

std::optional<std::array<uint8_t, 6>> resolveMacAddress(const std::string& iface, const pcpp::IPv4Address& ip) {
    const std::string ipString = ip.toString();
    if (auto cached = lookupArpCache(ipString); cached.has_value()) {
        return cached;
    }

    triggerArpResolution(iface, ipString);

    for (int attempt = 0; attempt < 5; ++attempt) {
        std::this_thread::sleep_for(std::chrono::milliseconds(100));
        if (auto cached = lookupArpCache(ipString); cached.has_value()) {
            return cached;
        }
    }

    return std::nullopt;
}
} // namespace

RoutingEngine::RoutingEngine() = default;

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
    auto* data = ipLayerPacket->getData();
    int length = static_cast<int>(ipLayerPacket->getDataLen());
    if (length <= 0 || data == nullptr) {
        std::cout << "[Routing] No packet data to forward." << std::endl;
        return;
    }

    auto sourceMac = getInterfaceMacAddress(route->interfaceName);
    if (!sourceMac.has_value()) {
        std::cout << "[Routing] Failed to resolve source MAC for " << route->interfaceName << std::endl;
        return;
    }

    pcpp::IPv4Address nextHop = (route->gateway.toString() == "0.0.0.0") ? destination : route->gateway;
    auto destinationMac = resolveMacAddress(route->interfaceName, nextHop);
    if (!destinationMac.has_value()) {
        std::cout << "[Routing] Failed to resolve destination MAC for " << nextHop.toString()
                  << " on " << route->interfaceName << std::endl;
        return;
    }

    std::vector<uint8_t> frame(kEthernetHeaderSize + static_cast<size_t>(length));
    std::memcpy(frame.data(), destinationMac->data(), destinationMac->size());
    std::memcpy(frame.data() + 6, sourceMac->data(), sourceMac->size());
    frame[12] = static_cast<uint8_t>((kEtherTypeIPv4 >> 8) & 0xFF);
    frame[13] = static_cast<uint8_t>(kEtherTypeIPv4 & 0xFF);
    std::memcpy(frame.data() + kEthernetHeaderSize, data, static_cast<size_t>(length));

    if (!outInterface->sendPacket(frame.data(), static_cast<int>(frame.size()))) {
        std::cout << "[Routing] Failed to send packet on " << route->interfaceName << std::endl;
        return;
    }

    std::cout << "[Routing] Forwarded packet to " << route->interfaceName << std::endl;
}
