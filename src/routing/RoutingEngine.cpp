#include "../../include/routing/RoutingEngine.h"

#include <algorithm>
#include <iostream>
#include <cstring>
#include <unordered_set>

#include "pcapplusplus/EthLayer.h"
#include "pcapplusplus/ArpLayer.h"
#include "pcapplusplus/TcpLayer.h"
#include "pcapplusplus/UdpLayer.h"
#include "pcapplusplus/SystemUtils.h"
#include <arpa/inet.h>

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

            for(int i=0; i<6; i++) {
                macVal = (macVal << 8) | macArr[i];
            }
            myMacAddresses.insert(macVal);
        }
    }
}


pcpp::PcapLiveDevice* RoutingEngine::findInterfaceByName(const std::string& name) const {
    auto it = std::find_if(interfaces.begin(), interfaces.end(),
                           [&](pcpp::PcapLiveDevice* d) { return d && d->getName() == name; });
    return (it == interfaces.end()) ? nullptr : *it;
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
    arpCache[ifName][ip.toInt()] = ArpEntry{ mac, std::chrono::steady_clock::now() + ArpTtl };
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
    pcpp::ArpLayer arp(pcpp::ARP_REPLY, myMac, myIp, dstMac, dstIp);

    pcpp::Packet arpPkt(64);
    arpPkt.addLayer(&eth);
    arpPkt.addLayer(&arp);
    arpPkt.computeCalculateFields();

    outInterface->sendPacket(&arpPkt, false);
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
    packet.computeCalculateFields();

    auto* raw = packet.getRawPacket();
    if (!raw) return;

    const uint8_t* data = raw->getRawData();
    const int len = raw->getRawDataLen();
    if (!data || len <= 0) return;

    std::lock_guard<std::mutex> lock(mtx);

    pending[ifName][nextHop.toInt()].clear();

    pending[ifName][nextHop.toInt()].emplace_back(data, data + len);
}

void RoutingEngine::processArpPacket(pcpp::Packet& packet, pcpp::PcapLiveDevice* inInterface) {
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

namespace {
struct TransportInfo
{
    uint16_t src_port{0};
    uint16_t dst_port{0};
    pcpp::ProtocolType protocol{pcpp::UnknownProtocol};
};

TransportInfo getTransportInfo(pcpp::Packet& packet, const pcpp::IPv4Layer& ipLayer)
{
    TransportInfo info;
    const auto protocol = ipLayer.getIPv4Header()->protocol;
    if (protocol == pcpp::PACKETPP_IPPROTO_TCP) {
        if (auto* tcp = packet.getLayerOfType<pcpp::TcpLayer>()) {
            info.src_port = ntohs(tcp->getTcpHeader()->portSrc);
            info.dst_port = ntohs(tcp->getTcpHeader()->portDst);
            info.protocol = pcpp::TCP;
        }
    } else if (protocol == pcpp::PACKETPP_IPPROTO_UDP) {
        if (auto* udp = packet.getLayerOfType<pcpp::UdpLayer>()) {
            info.src_port = ntohs(udp->getUdpHeader()->portSrc);
            info.dst_port = ntohs(udp->getUdpHeader()->portDst);
            info.protocol = pcpp::UDP;
        }
    } else if (protocol == pcpp::PACKETPP_IPPROTO_ICMP) {
        info.protocol = pcpp::ICMP;
    }
    return info;
}

void applyNatTranslation(NatSession& session, pcpp::Packet& packet, const TransportInfo& info)
{
    auto* ip = packet.getLayerOfType<pcpp::IPv4Layer>();
    if (!ip) {
        return;
    }

    const bool requires_ports = (info.protocol == pcpp::TCP || info.protocol == pcpp::UDP);
    const bool outbound_port_match = !requires_ports || info.src_port == session.getInternalPort();
    const bool inbound_port_match = !requires_ports || info.dst_port == session.getNatPort();

    if (session.isSourceNat()) {
        if (ip->getSrcIPv4Address() == session.getInternalIp() &&
            outbound_port_match) {
            ip->setSrcIPv4Address(session.getNatIp());
            if (auto* tcp = packet.getLayerOfType<pcpp::TcpLayer>()) {
                tcp->getTcpHeader()->portSrc = htons(session.getNatPort());
            } else if (auto* udp = packet.getLayerOfType<pcpp::UdpLayer>()) {
                udp->getUdpHeader()->portSrc = htons(session.getNatPort());
            }
        } else if (ip->getDstIPv4Address() == session.getNatIp() &&
                   inbound_port_match) {
            ip->setDstIPv4Address(session.getInternalIp());
            if (auto* tcp = packet.getLayerOfType<pcpp::TcpLayer>()) {
                tcp->getTcpHeader()->portDst = htons(session.getInternalPort());
            } else if (auto* udp = packet.getLayerOfType<pcpp::UdpLayer>()) {
                udp->getUdpHeader()->portDst = htons(session.getInternalPort());
            }
        }
    }
}
} // namespace

void RoutingEngine::routePacket(pcpp::Packet& packet,
                                pcpp::PcapLiveDevice* inInterface,
                                RoutingTable& routing_table,
                                const std::vector<NatPolicy>& nat_policies)
{
    auto* eth = packet.getLayerOfType<pcpp::EthLayer>();
    auto* ip  = packet.getLayerOfType<pcpp::IPv4Layer>();
    if (!eth || !ip) return;


    uint64_t srcMacVal = 0;
    uint8_t macArr[6];
    eth->getSourceMac().copyTo(macArr);
    for(int i=0; i<6; i++) srcMacVal = (srcMacVal << 8) | macArr[i];

    if (myMacAddresses.find(srcMacVal) != myMacAddresses.end()) {
        return;
    }

    if (inInterface) {
        learnArp(inInterface->getName(), ip->getSrcIPv4Address(), eth->getSourceMac());
    }

    const auto transport = getTransportInfo(packet, *ip);
    SessionFlowKey key{
        ip->getSrcIPv4Address(),
        transport.src_port,
        ip->getDstIPv4Address(),
        transport.dst_port,
        transport.protocol
    };
    bool nat_applied = false;
    if (auto* nat_session = NatPolicy::findSession(key)) {
        applyNatTranslation(*nat_session, packet, transport);
        nat_applied = true;
    }

    const pcpp::IPv4Address dst = ip->getDstIPv4Address();
    auto route = routing_table.findRoute(dst);

    if (!route.has_value()) return;

    pcpp::PcapLiveDevice* outInterface = findInterfaceByName(route->interfaceName);
    if (!outInterface) return;

    if (!nat_applied) {
        for (const auto& policy : nat_policies) {
            if (!policy.does_match_policy(*ip)) {
                continue;
            }
            auto translated_source = policy.getTranslatedSourceIp();
            if (translated_source == pcpp::IPv4Address::Zero) {
                translated_source = outInterface->getIPv4Address();
            }
            if (auto* nat_session = policy.getOrCreateSession(key, translated_source)) {
                applyNatTranslation(*nat_session, packet, transport);
                nat_applied = true;
            }
            break;
        }
    }

    auto* iphdr = ip->getIPv4Header();
    if (iphdr->timeToLive <= 1) return;
    iphdr->timeToLive -= 1;

    const pcpp::IPv4Address nextHop = ip->getDstIPv4Address();
    const std::string outIfName = outInterface->getName();

    auto macOpt = lookupArp(outIfName, nextHop);

    if (!macOpt.has_value()) {
        eth->setSourceMac(outInterface->getMacAddress());

        enqueuePending(outIfName, nextHop, packet);
        sendArpRequest(outInterface, nextHop);
        return;
    }

    eth->setSourceMac(outInterface->getMacAddress());
    eth->setDestMac(*macOpt);

    packet.computeCalculateFields();

    outInterface->sendPacket(&packet, false);
}
