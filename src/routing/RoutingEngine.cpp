#include "../../include/routing/RoutingEngine.h"

#include <algorithm>
#include <iostream>
#include <cstring>
#include <unordered_set>
#include <chrono>
#include <netinet/in.h>

#include "pcapplusplus/EthLayer.h"
#include "pcapplusplus/IPv4Layer.h"
#include "pcapplusplus/ArpLayer.h"
#include "pcapplusplus/Packet.h"
#include "pcapplusplus/SystemUtils.h"

RoutingEngine::RoutingEngine() = default;
static std::unordered_set<uint64_t> myMacAddresses;

void RoutingEngine::loadInterfaces(std::vector<pcpp::PcapLiveDevice*> ifs) {
    interfaces = std::move(ifs);
    myMacAddresses.clear();

    for(pcpp::PcapLiveDevice* interface : interfaces) {
        if(interface) {
            uint64_t macVal = 0;
            uint8_t macArr[6];
            interface->getMacAddress().copyTo(macArr);
            for (int i = 0; i < 6; i++) {
                macVal = (macVal << 8) | macArr[i];
            }
            myMacAddresses.insert(macVal);
        }
    }
}

pcpp::PcapLiveDevice* RoutingEngine::findInterfaceByName(const std::string& name) const {
    auto it = std::find_if(interfaces.begin(), interfaces.end(),
                           [&](pcpp::PcapLiveDevice* d) { return d && d->getName() == name; });
    return (it != interfaces.end()) ? *it : nullptr;
}


std::optional<pcpp::MacAddress> RoutingEngine::lookupArp(const std::string& ifName, const pcpp::IPv4Address& ip) {
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

void RoutingEngine::learnArp(const std::string& ifName, const pcpp::IPv4Address& ip, const pcpp::MacAddress& mac) {
    if (ip == pcpp::IPv4Address::Zero || mac == pcpp::MacAddress::Zero) return;
    std::lock_guard<std::mutex> lock(mtx);
    arpCache[ifName][ip.toInt()] = ArpEntry{mac, std::chrono::steady_clock::now() + std::chrono::minutes(20)};

}

void RoutingEngine::sendArpRequest(pcpp::PcapLiveDevice* outInterface, const pcpp::IPv4Address& targetIp)
{
    if (!outInterface) return;

    const pcpp::IPv4Address srcIp = outInterface->getIPv4Address();
    if (srcIp == pcpp::IPv4Address::Zero) return;

    const pcpp::MacAddress srcMac = outInterface->getMacAddress();

    pcpp::EthLayer eth(srcMac, pcpp::MacAddress::Broadcast, PCPP_ETHERTYPE_ARP);
    pcpp::ArpLayer arp(pcpp::ARP_REQUEST, srcMac, srcIp, pcpp::MacAddress::Zero, targetIp);

    pcpp::Packet arpPkt(64);
    arpPkt.addLayer(&eth);
    arpPkt.addLayer(&arp);
    arpPkt.computeCalculateFields();

    outInterface->sendPacket(&arpPkt);
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
    pcpp::ArpLayer arp(pcpp::ARP_REPLY, myMac, myIp, dstMac, dstIp);

    pcpp::Packet arpPkt(64);
    arpPkt.addLayer(&eth);
    arpPkt.addLayer(&arp);
    arpPkt.computeCalculateFields();

    outInterface->sendPacket(&arpPkt);
}

void RoutingEngine::flushPending(const std::string& ifName, const pcpp::IPv4Address& ip, const pcpp::MacAddress& mac)
{
    pcpp::PcapLiveDevice* out = findInterfaceByName(ifName);
    if (!out) return;

    std::vector<std::vector<uint8_t>> frames;
    std::lock_guard<std::mutex> lock(mtx);

    auto itIf = pending.find(ifName);
    if (itIf == pending.end()) return;

    auto itIp = itIf->second.find(ip.toInt());
    if (itIp == itIf->second.end()) return;

    frames = std::move(itIp->second);
    itIf->second.erase(itIp);


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


void RoutingEngine::enqueuePending(const std::string& ifName, const pcpp::IPv4Address& nextHop, pcpp::Packet& packet) {
    auto* raw = packet.getRawPacket();
    if (!raw) return;

    const uint8_t* data = raw->getRawData();
    const int len = raw->getRawDataLen();
    if (!data || len <= 0) return;

    std::lock_guard<std::mutex> lock(mtx);
    if (pending[ifName][nextHop.toInt()].size() < 10) {
        pending[ifName][nextHop.toInt()].emplace_back(data, data + len);
    }
}

void RoutingEngine::processArpPacket(pcpp::Packet& packet, pcpp::PcapLiveDevice* inInterface) {
    if (!inInterface) return;
    auto* arp = packet.getLayerOfType<pcpp::ArpLayer>();
    if (!arp) return;

    const std::string ifName = inInterface->getName();
    learnArp(ifName, arp->getSenderIpAddr(), arp->getSenderMacAddress());

    if (ntohs(arp->getArpHeader()->opcode) == pcpp::ARP_REQUEST) {
        if (arp->getTargetIpAddr() == inInterface->getIPv4Address()) {
            sendArpReply(inInterface, arp->getSenderMacAddress(), arp->getSenderIpAddr());
        }
    }
    flushPending(ifName, arp->getSenderIpAddr(), arp->getSenderMacAddress());
}


void RoutingEngine::routePacket(pcpp::Packet& packet, pcpp::PcapLiveDevice* inInterface, RoutingTable& routing_table)
{
    auto* eth = packet.getLayerOfType<pcpp::EthLayer>();
    auto* ip  = packet.getLayerOfType<pcpp::IPv4Layer>();
    if (!eth || !ip) return;
    const pcpp::IPv4Address dst = ip->getDstIPv4Address();

    for (const auto* dev : interfaces) {
        if (dev->getIPv4Address() == dst) {
            return;
        }
    }
    auto route = routing_table.findRoute(dst);

    if (!route.has_value()) {
        return;
    }


    pcpp::IPv4Address nextHop = dst;
    if (route->gateway != pcpp::IPv4Address("0.0.0.0")) {
        nextHop = route->gateway;
    }

    if (findInterfaceByName(route->interfaceName)->getIPv4Address() == nextHop) {
        return;
    }

    pcpp::PcapLiveDevice* outInterface = findInterfaceByName(route->interfaceName);
    if (!outInterface) return;

    auto* iphdr = ip->getIPv4Header();
    if (iphdr->timeToLive <= 1) return;
    iphdr->timeToLive -= 1;
    packet.computeCalculateFields();
    eth->setSourceMac(outInterface->getMacAddress());

    auto macOpt = lookupArp(outInterface->getName(), nextHop);

    if (macOpt) {
        eth->setDestMac(*macOpt);
        if (!outInterface->sendPacket(&packet)) {
            std::cerr << "[Routing] Failed to send packet on " << outInterface->getName() << std::endl;
        }
    } else {
        enqueuePending(outInterface->getName(), nextHop, packet);
        sendArpRequest(outInterface, nextHop);
    }
}