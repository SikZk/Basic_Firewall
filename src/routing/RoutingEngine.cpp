#include "../../include/routing/RoutingEngine.h"

#include <algorithm>
#include <iostream>
#include <cstring>
#include <unordered_set>

#include "pcapplusplus/EthLayer.h"
#include "pcapplusplus/ArpLayer.h"
#include "pcapplusplus/SystemUtils.h"

RoutingTable RoutingEngine::routing_table;

RoutingEngine::RoutingEngine() = default;

// Helper to cache our own MACs for fast loop detection
static std::unordered_set<uint64_t> myMacAddresses;

void RoutingEngine::loadInterfaces(std::vector<pcpp::PcapLiveDevice*> ifs)
{
    interfaces = std::move(ifs);

    // Cache our MACs to detect loops
    myMacAddresses.clear();
    for(auto* dev : interfaces) {
        if(dev) {
            // Convert MAC to 64-bit int for fast hashing/lookup
            uint64_t macVal = 0;
            uint8_t macArr[6];
            dev->getMacAddress().copyTo(macArr);
            // Simple byte shift to make a unique ID
            for(int i=0; i<6; i++) {
                macVal = (macVal << 8) | macArr[i];
            }
            myMacAddresses.insert(macVal);
        }
    }
}

// ... [Keep loadRoutingTable, findInterfaceByName, lookupArp, learnArp as they were] ...

void RoutingEngine::loadRoutingTable(const RoutingTable& table)
{
    routing_table = table;
}

pcpp::PcapLiveDevice* RoutingEngine::findInterfaceByName(const std::string& name) const
{
    auto it = std::find_if(interfaces.begin(), interfaces.end(),
                           [&](pcpp::PcapLiveDevice* d) { return d && d->getName() == name; });
    return (it == interfaces.end()) ? nullptr : *it;
}

std::optional<pcpp::MacAddress> RoutingEngine::lookupArp(const std::string& ifName, const pcpp::IPv4Address& ip)
{
    std::lock_guard<std::mutex> lock(mtx);
    auto itIf = arpCache.find(ifName);
    if (itIf == arpCache.end()) return std::nullopt;

    const uint32_t key = ip.toInt();
    auto it = itIf->second.find(key);
    if (it == itIf->second.end()) return std::nullopt;

    if (std::chrono::steady_clock::now() > it->second.expiresAt) {
        itIf->second.erase(it);
        return std::nullopt;
    }
    return it->second.mac;
}

void RoutingEngine::learnArp(const std::string& ifName, const pcpp::IPv4Address& ip, const pcpp::MacAddress& mac)
{
    if (ip == pcpp::IPv4Address::Zero || mac == pcpp::MacAddress::Zero) return;
    std::lock_guard<std::mutex> lock(mtx);
    arpCache[ifName][ip.toInt()] = ArpEntry{ mac, std::chrono::steady_clock::now() + ArpTtl };
}

// ... [Keep sendArpRequest, sendArpReply] ...
void RoutingEngine::sendArpRequest(pcpp::PcapLiveDevice* outInterface, const pcpp::IPv4Address& targetIp)
{
    if (!outInterface) return;

    const pcpp::IPv4Address srcIp = outInterface->getIPv4Address();
    if (srcIp == pcpp::IPv4Address::Zero) return;

    const pcpp::MacAddress srcMac = outInterface->getMacAddress();

    pcpp::EthLayer eth(srcMac, pcpp::MacAddress::Broadcast, PCPP_ETHERTYPE_ARP);

    // NON-deprecated overload: (opCode, senderMac, senderIp, targetMac, targetIp) :contentReference[oaicite:4]{index=4}
    pcpp::ArpLayer arp(pcpp::ARP_REQUEST, srcMac, srcIp, pcpp::MacAddress::Zero, targetIp);

    pcpp::Packet arpPkt(64);
    arpPkt.addLayer(&eth);
    arpPkt.addLayer(&arp);
    arpPkt.computeCalculateFields();

    outInterface->sendPacket(&arpPkt, false);
}

void RoutingEngine::sendArpReply(pcpp::PcapLiveDevice* outInterface,
                                 const pcpp::MacAddress& dstMac,
                                 const pcpp::IPv4Address& dstIp)
{
    if (!outInterface) return;

    const pcpp::IPv4Address myIp = outInterface->getIPv4Address();
    if (myIp == pcpp::IPv4Address::Zero) return;

    const pcpp::MacAddress myMac = outInterface->getMacAddress();

    pcpp::EthLayer eth(myMac, dstMac, PCPP_ETHERTYPE_ARP);

    // NON-deprecated overload: (opCode, senderMac, senderIp, targetMac, targetIp) :contentReference[oaicite:5]{index=5}
    pcpp::ArpLayer arp(pcpp::ARP_REPLY, myMac, myIp, dstMac, dstIp);

    pcpp::Packet arpPkt(64);
    arpPkt.addLayer(&eth);
    arpPkt.addLayer(&arp);
    arpPkt.computeCalculateFields();

    outInterface->sendPacket(&arpPkt, false);
}

// ... [Keep flushPending with no changes] ...
void RoutingEngine::flushPending(const std::string& ifName, const pcpp::IPv4Address& ip, const pcpp::MacAddress& mac)
{
    pcpp::PcapLiveDevice* out = findInterfaceByName(ifName);
    if (!out) return;

    std::vector<std::vector<uint8_t>> frames;
    {
        std::lock_guard<std::mutex> lock(mtx);
        auto itIf = pending.find(ifName);
        if (itIf == pending.end()) return;

        auto itIp = itIf->second.find(ip.toInt());
        if (itIp == itIf->second.end()) return;

        frames = std::move(itIp->second);
        itIf->second.erase(itIp);
    }

    uint8_t dst[6];
    mac.copyTo(dst);
    uint8_t src[6];
    out->getMacAddress().copyTo(src);

    for (auto& f : frames) {
        if (f.size() < 14) continue;
        std::memcpy(f.data(), dst, 6);
        std::memcpy(f.data() + 6, src, 6);
        out->sendPacket(f.data(), (int)f.size());
    }
}

// UPDATED: enqueuePending
void RoutingEngine::enqueuePending(const std::string& ifName, const pcpp::IPv4Address& nextHop, pcpp::Packet& packet)
{
    packet.computeCalculateFields(); // Finalize checksums/lengths before buffering

    auto* raw = packet.getRawPacket();
    if (!raw) return;

    const uint8_t* data = raw->getRawData();
    const int len = raw->getRawDataLen();
    if (!data || len <= 0) return;

    std::lock_guard<std::mutex> lock(mtx);

    // FIX 1: Clear previous queue to prevent duplicate packets upon ARP resolution
    pending[ifName][nextHop.toInt()].clear();

    pending[ifName][nextHop.toInt()].emplace_back(data, data + len);
}

// ... [processArpPacket same as before] ...
void RoutingEngine::processArpPacket(pcpp::Packet& packet, pcpp::PcapLiveDevice* inInterface)
{
    if (!inInterface) return;
    auto* arp = packet.getLayerOfType<pcpp::ArpLayer>();
    if (!arp) return;

    const std::string ifName = inInterface->getName();
    learnArp(ifName, arp->getSenderIpAddr(), arp->getSenderMacAddress());

    if (pcpp::netToHost16(arp->getArpHeader()->opcode) == pcpp::ARP_REQUEST) {
        if (arp->getTargetIpAddr() == inInterface->getIPv4Address()) {
            sendArpReply(inInterface, arp->getSenderMacAddress(), arp->getSenderIpAddr());
        }
    }
    flushPending(ifName, arp->getSenderIpAddr(), arp->getSenderMacAddress());
}

// CRITICAL UPDATE: routePacket
void RoutingEngine::routePacket(pcpp::Packet& packet, pcpp::PcapLiveDevice* inInterface)
{
    auto* eth = packet.getLayerOfType<pcpp::EthLayer>();
    auto* ip  = packet.getLayerOfType<pcpp::IPv4Layer>();
    if (!eth || !ip) return;

    // --- FIX 2: GLOBAL LOOP PROTECTION ---
    // Calculate the integer value of the Source MAC
    uint64_t srcMacVal = 0;
    uint8_t macArr[6];
    eth->getSourceMac().copyTo(macArr);
    for(int i=0; i<6; i++) srcMacVal = (srcMacVal << 8) | macArr[i];

    // If the sender is US (any of our interfaces), DROP IT.
    // This stops loops where packet goes out eth0 and comes back in eth1.
    if (myMacAddresses.find(srcMacVal) != myMacAddresses.end()) {
        return;
    }

    // Passive ARP learning
    if (inInterface) {
        learnArp(inInterface->getName(), ip->getSrcIPv4Address(), eth->getSourceMac());
    }

    const pcpp::IPv4Address dst = ip->getDstIPv4Address();
    auto route = routing_table.findRoute(dst);

    // --- FIX 3: Performance ---
    // Remove cout to stop latency
    if (!route.has_value()) return;

    pcpp::PcapLiveDevice* outInterface = findInterfaceByName(route->interfaceName);
    if (!outInterface) return;

    // TTL Check
    auto* iphdr = ip->getIPv4Header();
    if (iphdr->timeToLive <= 1) return; // Drop
    iphdr->timeToLive -= 1;             // Decrement

    const pcpp::IPv4Address nextHop = dst; // Modify if you add Gateway support
    const std::string outIfName = outInterface->getName();

    auto macOpt = lookupArp(outIfName, nextHop);

    if (!macOpt.has_value()) {
        // Prepare frame for buffering (Set Source MAC to ours immediately)
        eth->setSourceMac(outInterface->getMacAddress());
        // Dest MAC is unknown, will be overwritten in flushPending

        enqueuePending(outIfName, nextHop, packet);
        sendArpRequest(outInterface, nextHop);
        return;
    }

    // Fast Path
    eth->setSourceMac(outInterface->getMacAddress());
    eth->setDestMac(*macOpt);

    packet.computeCalculateFields(); // Recalculate checksums (IP/TCP/UDP)

    outInterface->sendPacket(&packet, false);
}