#pragma once

#include <vector>
#include <string>
#include <unordered_map>
#include <optional>
#include <mutex>
#include <chrono>

#include "pcapplusplus/PcapLiveDevice.h"
#include "../routing/RoutingTable.h"

class RoutingEngine
{
public:
    RoutingEngine();

    void loadInterfaces(std::vector<pcpp::PcapLiveDevice*> interfaces);
    void loadRoutingTable(const RoutingTable& table);

    // Called from capture callback:
    void processArpPacket(pcpp::Packet& packet, pcpp::PcapLiveDevice* inInterface);
    void routePacket(pcpp::Packet& packet, pcpp::PcapLiveDevice* inInterface, RoutingTable& routing_table);

private:
    struct ArpEntry
    {
        pcpp::MacAddress mac;
        std::chrono::steady_clock::time_point expiresAt;
    };

    std::unordered_map<std::string, std::unordered_map<uint32_t, ArpEntry>> arpCache;

    std::unordered_map<std::string, std::unordered_map<uint32_t, std::vector<std::vector<uint8_t>>>> pending;

    std::mutex mtx;

    std::vector<pcpp::PcapLiveDevice*> interfaces;
    static RoutingTable routing_table;

    static constexpr auto ArpTtl = std::chrono::minutes(5);

    pcpp::PcapLiveDevice* findInterfaceByName(const std::string& name) const;

    std::optional<pcpp::MacAddress> lookupArp(const std::string& ifName, const pcpp::IPv4Address& ip);
    void learnArp(const std::string& ifName, const pcpp::IPv4Address& ip, const pcpp::MacAddress& mac);

    void sendArpRequest(pcpp::PcapLiveDevice* outInterface, const pcpp::IPv4Address& targetIp);
    void sendArpReply(pcpp::PcapLiveDevice* outInterface,
                      const pcpp::MacAddress& dstMac,
                      const pcpp::IPv4Address& dstIp);

    void enqueuePending(const std::string& ifName, const pcpp::IPv4Address& nextHop, pcpp::Packet& packet);
    void flushPending(const std::string& ifName, const pcpp::IPv4Address& ip, const pcpp::MacAddress& mac);
};
