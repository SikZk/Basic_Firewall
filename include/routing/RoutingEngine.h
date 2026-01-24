#pragma once

#include <vector>
#include <string>
#include <unordered_map>
#include <optional>
#include <mutex>
#include <chrono>

#include "pcapplusplus/PcapLiveDevice.h"
#include "../routing/RoutingTable.h"

/**
 * @brief Handles routing decisions and ARP resolution.
 */
class RoutingEngine
{
public:
    /**
     * @brief Construct a routing engine.
     */
    RoutingEngine();

    /**
     * @brief Load capture interfaces to use for routing.
     *
     * @param interfaces List of interfaces.
     */
    void loadInterfaces(std::vector<pcpp::PcapLiveDevice*> interfaces);
    /**
     * @brief Load a routing table snapshot.
     *
     * @param table Routing table to use.
     */
    void loadRoutingTable(const RoutingTable& table);

    /**
     * @brief Process an incoming ARP packet.
     *
     * @param packet Packet containing ARP layer.
     * @param inInterface Interface the packet arrived on.
     */
    void processArpPacket(pcpp::Packet& packet, pcpp::PcapLiveDevice* inInterface);
    /**
     * @brief Route an IPv4 packet based on routing table.
     *
     * @param packet Packet to route.
     * @param inInterface Interface the packet arrived on.
     * @param routing_table Routing table to consult.
     */
    void routePacket(pcpp::Packet& packet, pcpp::PcapLiveDevice* inInterface, RoutingTable& routing_table);

private:
    /**
     * @brief ARP cache entry.
     */
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

    /**
     * @brief Find an interface by its name.
     *
     * @param name Interface name.
     * @return Pointer to the interface or nullptr.
     */
    pcpp::PcapLiveDevice* findInterfaceByName(const std::string& name) const;

    /**
     * @brief Look up an ARP entry for a next hop.
     *
     * @param ifName Interface name.
     * @param ip Target IP address.
     * @return MAC address if cached.
     */
    std::optional<pcpp::MacAddress> lookupArp(const std::string& ifName, const pcpp::IPv4Address& ip);
    /**
     * @brief Learn a MAC address for a given IP on an interface.
     *
     * @param ifName Interface name.
     * @param ip IP address to map.
     * @param mac MAC address to cache.
     */
    void learnArp(const std::string& ifName, const pcpp::IPv4Address& ip, const pcpp::MacAddress& mac);

    /**
     * @brief Send an ARP request for a target IP.
     *
     * @param outInterface Interface to send from.
     * @param targetIp IP address to resolve.
     */
    void sendArpRequest(pcpp::PcapLiveDevice* outInterface, const pcpp::IPv4Address& targetIp);
    /**
     * @brief Send an ARP reply to a requester.
     *
     * @param outInterface Interface to send from.
     * @param dstMac Destination MAC address.
     * @param dstIp Destination IP address.
     */
    void sendArpReply(pcpp::PcapLiveDevice* outInterface,
                      const pcpp::MacAddress& dstMac,
                      const pcpp::IPv4Address& dstIp);

    /**
     * @brief Queue a packet until ARP resolution completes.
     *
     * @param ifName Interface name.
     * @param nextHop Next hop IP address.
     * @param packet Packet to enqueue.
     */
    void enqueuePending(const std::string& ifName, const pcpp::IPv4Address& nextHop, pcpp::Packet& packet);
    /**
     * @brief Flush queued packets after ARP resolution.
     *
     * @param ifName Interface name.
     * @param ip IP address resolved.
     * @param mac Resolved MAC address.
     */
    void flushPending(const std::string& ifName, const pcpp::IPv4Address& ip, const pcpp::MacAddress& mac);
};
