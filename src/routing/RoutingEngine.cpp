#include "../../include/routing/RoutingEngine.h"
#include <algorithm>
#include <array>
#include <chrono>
#include <fstream>
#include <iostream>
#include <optional>
#include <sstream>
#include <string>
#include <thread>
#include <vector>
#include <arpa/inet.h>
#include <cstdlib>
#include <cstring>
#include "pcapplusplus/PcapLiveDeviceList.h"
#include "pcapplusplus/PcapLiveDevice.h"

RoutingTable RoutingEngine::routing_table;

namespace {
constexpr size_t kMacLength = 6;
constexpr size_t kEthernetHeaderLength = 14;
constexpr size_t kArpPacketLength = 28;
constexpr uint16_t kEtherTypeIPv4 = 0x0800;
constexpr uint16_t kEtherTypeArp = 0x0806;
constexpr uint16_t kArpHardwareTypeEthernet = 1;
constexpr uint16_t kArpOpRequest = 1;

bool parseMacString(const std::string& macString, std::array<uint8_t, kMacLength>& macBytes)
{
    std::istringstream stream(macString);
    std::string segment;
    size_t index = 0;
    while (std::getline(stream, segment, ':')) {
        if (segment.size() != 2 || index >= kMacLength) {
            return false;
        }
        char* end = nullptr;
        unsigned long value = std::strtoul(segment.c_str(), &end, 16);
        if (end == nullptr || *end != '\0' || value > 0xFF) {
            return false;
        }
        macBytes[index++] = static_cast<uint8_t>(value);
    }
    return index == kMacLength;
}

std::optional<std::array<uint8_t, kMacLength>> lookupMacInArpCache(
    const pcpp::IPv4Address& ip,
    const std::string& interfaceName
)
{
    std::ifstream arpFile("/proc/net/arp");
    if (!arpFile) {
        return std::nullopt;
    }

    std::string line;
    std::getline(arpFile, line);
    while (std::getline(arpFile, line)) {
        std::istringstream lineStream(line);
        std::string ipAddress;
        std::string hwType;
        std::string flags;
        std::string macAddress;
        std::string mask;
        std::string device;
        if (!(lineStream >> ipAddress >> hwType >> flags >> macAddress >> mask >> device)) {
            continue;
        }
        if (device != interfaceName || ipAddress != ip.toString()) {
            continue;
        }
        if (macAddress == "00:00:00:00:00:00") {
            return std::nullopt;
        }
        std::array<uint8_t, kMacLength> macBytes{};
        if (!parseMacString(macAddress, macBytes)) {
            return std::nullopt;
        }
        return macBytes;
    }
    return std::nullopt;
}

bool sendArpRequest(pcpp::PcapLiveDevice* device, const pcpp::IPv4Address& targetIp)
{
    if (device == nullptr) {
        return false;
    }

    std::array<uint8_t, kMacLength> srcMacBytes{};
    if (!parseMacString(device->getMacAddress().toString(), srcMacBytes)) {
        return false;
    }

    std::array<uint8_t, kMacLength> dstMacBytes{};
    dstMacBytes.fill(0xFF);

    in_addr senderIp{};
    in_addr targetAddr{};
    if (inet_pton(AF_INET, device->getIPv4Address().toString().c_str(), &senderIp) != 1) {
        return false;
    }
    if (inet_pton(AF_INET, targetIp.toString().c_str(), &targetAddr) != 1) {
        return false;
    }

    std::array<uint8_t, kEthernetHeaderLength + kArpPacketLength> packet{};
    std::copy(dstMacBytes.begin(), dstMacBytes.end(), packet.begin());
    std::copy(srcMacBytes.begin(), srcMacBytes.end(), packet.begin() + kMacLength);
    uint16_t etherType = htons(kEtherTypeArp);
    std::memcpy(packet.data() + 12, &etherType, sizeof(etherType));

    size_t offset = kEthernetHeaderLength;
    uint16_t hardwareType = htons(kArpHardwareTypeEthernet);
    std::memcpy(packet.data() + offset, &hardwareType, sizeof(hardwareType));
    offset += sizeof(hardwareType);
    uint16_t protocolType = htons(kEtherTypeIPv4);
    std::memcpy(packet.data() + offset, &protocolType, sizeof(protocolType));
    offset += sizeof(protocolType);
    packet[offset++] = static_cast<uint8_t>(kMacLength);
    packet[offset++] = static_cast<uint8_t>(sizeof(in_addr));
    uint16_t opcode = htons(kArpOpRequest);
    std::memcpy(packet.data() + offset, &opcode, sizeof(opcode));
    offset += sizeof(opcode);
    std::memcpy(packet.data() + offset, srcMacBytes.data(), kMacLength);
    offset += kMacLength;
    std::memcpy(packet.data() + offset, &senderIp, sizeof(senderIp));
    offset += sizeof(senderIp);
    std::array<uint8_t, kMacLength> zeroMac{};
    std::memcpy(packet.data() + offset, zeroMac.data(), kMacLength);
    offset += kMacLength;
    std::memcpy(packet.data() + offset, &targetAddr, sizeof(targetAddr));

    return device->sendPacket(packet.data(), static_cast<int>(packet.size()));
}

std::optional<std::array<uint8_t, kMacLength>> resolveMacAddress(
    pcpp::PcapLiveDevice* device,
    const pcpp::IPv4Address& targetIp
)
{
    if (device == nullptr) {
        return std::nullopt;
    }

    auto cached = lookupMacInArpCache(targetIp, device->getName());
    if (cached.has_value()) {
        return cached;
    }

    for (int attempt = 0; attempt < 3; ++attempt) {
        if (!sendArpRequest(device, targetIp)) {
            continue;
        }
        std::this_thread::sleep_for(std::chrono::milliseconds(100));
        cached = lookupMacInArpCache(targetIp, device->getName());
        if (cached.has_value()) {
            return cached;
        }
    }
    return std::nullopt;
}

bool sendEthernetPacket(
    pcpp::PcapLiveDevice* device,
    const std::array<uint8_t, kMacLength>& dstMac,
    const pcpp::IPv4Layer* ipLayerPacket
)
{
    if (device == nullptr || ipLayerPacket == nullptr) {
        return false;
    }

    std::array<uint8_t, kMacLength> srcMac{};
    if (!parseMacString(device->getMacAddress().toString(), srcMac)) {
        return false;
    }

    const uint8_t* ipData = ipLayerPacket->getData();
    int ipLength = static_cast<int>(ipLayerPacket->getDataLen());
    if (ipData == nullptr || ipLength <= 0) {
        return false;
    }

    std::vector<uint8_t> frame(static_cast<size_t>(kEthernetHeaderLength + ipLength));
    std::copy(dstMac.begin(), dstMac.end(), frame.begin());
    std::copy(srcMac.begin(), srcMac.end(), frame.begin() + kMacLength);
    uint16_t etherType = htons(kEtherTypeIPv4);
    std::memcpy(frame.data() + 12, &etherType, sizeof(etherType));
    std::memcpy(frame.data() + kEthernetHeaderLength, ipData, static_cast<size_t>(ipLength));

    return device->sendPacket(frame.data(), static_cast<int>(frame.size()));
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
    pcpp::IPv4Address nextHop = route->gateway;
    if (nextHop.toString() == "0.0.0.0") {
        nextHop = destination;
    }

    auto nextHopMac = resolveMacAddress(outInterface, nextHop);
    if (!nextHopMac.has_value()) {
        std::cout << "[Routing] Failed to resolve MAC for " << nextHop.toString()
                  << " on " << route->interfaceName << std::endl;
        return;
    }

    if (!sendEthernetPacket(outInterface, nextHopMac.value(), ipLayerPacket)) {
        std::cout << "[Routing] Failed to send packet on " << route->interfaceName << std::endl;
        return;
    }

    std::cout << "[Routing] Forwarded packet to " << route->interfaceName
              << " via " << nextHop.toString() << std::endl;
}
