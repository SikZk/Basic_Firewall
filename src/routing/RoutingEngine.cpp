#include "../../include/routing/RoutingEngine.h"

#include <algorithm>
#include <iostream>
#include <cstring>
#include <unordered_set>
#include <netinet/in.h>

#include "pcapplusplus/EthLayer.h"
#include "pcapplusplus/ArpLayer.h"
#include "pcapplusplus/TcpLayer.h"
#include "pcapplusplus/UdpLayer.h"
#include "pcapplusplus/SystemUtils.h"

RoutingEngine::RoutingEngine() = default;
static std::unordered_set<uint64_t> myMacAddresses;

namespace {
struct IcmpEchoHeader {
    uint8_t type;
    uint8_t code;
    uint16_t checksum;
    uint16_t identifier;
    uint16_t sequence;
};

bool matchesNetwork(const pcpp::IPv4Address& address, const pcpp::IPv4Address& network, uint32_t maskBits)
{
    if (maskBits == 0) {
        return true;
    }
    uint32_t mask = maskBits >= 32 ? 0xFFFFFFFFu : (0xFFFFFFFFu << (32 - maskBits));
    return (address.toInt() & mask) == (network.toInt() & mask);
}

bool isInternalAddress(const pcpp::IPv4Address& address)
{
    return matchesNetwork(address, pcpp::IPv4Address("10.0.0.0"), 8);
}

uint16_t computeChecksum(const uint8_t* data, size_t len)
{
    uint32_t sum = 0;
    const uint16_t* ptr = reinterpret_cast<const uint16_t*>(data);
    while (len > 1) {
        sum += *ptr++;
        len -= 2;
    }
    if (len > 0) {
        sum += static_cast<uint16_t>(*(reinterpret_cast<const uint8_t*>(ptr)) << 8);
    }
    while (sum >> 16) {
        sum = (sum & 0xFFFF) + (sum >> 16);
    }
    return static_cast<uint16_t>(~sum);
}

bool getIcmpEchoFields(pcpp::IPv4Layer* ipLayer, uint16_t& identifier, uint16_t& sequence)
{
    if (!ipLayer) {
        return false;
    }
    uint8_t* payload = ipLayer->getLayerPayload();
    size_t payload_len = ipLayer->getLayerPayloadSize();
    if (!payload || payload_len < sizeof(IcmpEchoHeader)) {
        return false;
    }
    auto* hdr = reinterpret_cast<IcmpEchoHeader*>(payload);
    if (hdr->type != 0 && hdr->type != 8) {
        return false;
    }
    identifier = ntohs(hdr->identifier);
    sequence = ntohs(hdr->sequence);
    return true;
}

void setIcmpEchoFields(pcpp::IPv4Layer* ipLayer, uint16_t identifier, uint16_t sequence)
{
    if (!ipLayer) {
        return;
    }
    uint8_t* payload = ipLayer->getLayerPayload();
    size_t payload_len = ipLayer->getLayerPayloadSize();
    if (!payload || payload_len < sizeof(IcmpEchoHeader)) {
        return;
    }
    auto* hdr = reinterpret_cast<IcmpEchoHeader*>(payload);
    if (hdr->type != 0 && hdr->type != 8) {
        return;
    }
    hdr->identifier = htons(identifier);
    hdr->sequence = htons(sequence);
    hdr->checksum = 0;
    hdr->checksum = htons(computeChecksum(payload, payload_len));
}

struct TransportInfo {
    pcpp::ProtocolType protocol{pcpp::UnknownProtocol};
    uint16_t src_port{0};
    uint16_t dst_port{0};
    bool is_icmp{false};
};

bool getTransportInfo(pcpp::Packet& packet, pcpp::IPv4Layer* ipLayer, TransportInfo& info)
{
    if (!ipLayer) {
        return false;
    }
    const uint8_t proto = ipLayer->getIPv4Header()->protocol;
    if (proto == IPPROTO_TCP) {
        auto* tcp = packet.getLayerOfType<pcpp::TcpLayer>();
        if (!tcp) {
            return false;
        }
        info.protocol = pcpp::TCP;
        info.src_port = ntohs(tcp->getTcpHeader()->portSrc);
        info.dst_port = ntohs(tcp->getTcpHeader()->portDst);
        return true;
    }
    if (proto == IPPROTO_UDP) {
        auto* udp = packet.getLayerOfType<pcpp::UdpLayer>();
        if (!udp) {
            return false;
        }
        info.protocol = pcpp::UDP;
        info.src_port = ntohs(udp->getUdpHeader()->portSrc);
        info.dst_port = ntohs(udp->getUdpHeader()->portDst);
        return true;
    }
    if (proto == IPPROTO_ICMP) {
        uint16_t identifier = 0;
        uint16_t sequence = 0;
        if (!getIcmpEchoFields(ipLayer, identifier, sequence)) {
            return false;
        }
        info.protocol = pcpp::ICMP;
        info.src_port = identifier;
        info.dst_port = sequence;
        info.is_icmp = true;
        return true;
    }
    return false;
}

void setTransportSourcePort(pcpp::Packet& packet, pcpp::IPv4Layer* ipLayer, const TransportInfo& info, uint16_t port)
{
    if (info.protocol == pcpp::TCP) {
        if (auto* tcp = packet.getLayerOfType<pcpp::TcpLayer>()) {
            tcp->getTcpHeader()->portSrc = htons(port);
        }
        return;
    }
    if (info.protocol == pcpp::UDP) {
        if (auto* udp = packet.getLayerOfType<pcpp::UdpLayer>()) {
            udp->getUdpHeader()->portSrc = htons(port);
        }
        return;
    }
    if (info.protocol == pcpp::ICMP) {
        setIcmpEchoFields(ipLayer, port, info.dst_port);
    }
}

void setTransportDestinationPort(pcpp::Packet& packet, pcpp::IPv4Layer* ipLayer, const TransportInfo& info, uint16_t port)
{
    if (info.protocol == pcpp::TCP) {
        if (auto* tcp = packet.getLayerOfType<pcpp::TcpLayer>()) {
            tcp->getTcpHeader()->portDst = htons(port);
        }
        return;
    }
    if (info.protocol == pcpp::UDP) {
        if (auto* udp = packet.getLayerOfType<pcpp::UdpLayer>()) {
            udp->getUdpHeader()->portDst = htons(port);
        }
        return;
    }
    if (info.protocol == pcpp::ICMP) {
        setIcmpEchoFields(ipLayer, port, info.dst_port);
    }
}
} // namespace

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

void RoutingEngine::routePacket(pcpp::Packet& packet, pcpp::PcapLiveDevice* inInterface, RoutingTable& routing_table)
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

    const pcpp::IPv4Address original_src = ip->getSrcIPv4Address();
    const pcpp::IPv4Address original_dst = ip->getDstIPv4Address();

    TransportInfo transport;
    const bool has_transport = getTransportInfo(packet, ip, transport);

    if (has_transport) {
        SessionFlowKey translated_key{
            ip->getSrcIPv4Address(),
            transport.src_port,
            ip->getDstIPv4Address(),
            transport.dst_port,
            transport.protocol
        };
        if (auto* nat_session = nat_state.findByTranslatedKey(translated_key)) {
            ip->setDstIPv4Address(nat_session->getSourceToDestinationFlow().internal_ip);
            setTransportDestinationPort(
                packet,
                ip,
                transport,
                nat_session->getSourceToDestinationFlow().internal_port
            );
        }
    }

    const pcpp::IPv4Address dst = ip->getDstIPv4Address();
    auto route = routing_table.findRoute(dst);

    if (!route.has_value()) return;

    pcpp::PcapLiveDevice* outInterface = findInterfaceByName(route->interfaceName);
    if (!outInterface) return;

    auto* iphdr = ip->getIPv4Header();
    if (iphdr->timeToLive <= 1) return;
    iphdr->timeToLive -= 1;

    if (has_transport && isInternalAddress(original_src) && !isInternalAddress(original_dst)) {
        SessionFlowKey outbound_key{
            original_src,
            transport.src_port,
            original_dst,
            transport.dst_port,
            transport.protocol
        };
        if (auto* nat_session = nat_state.getOrCreateSession(outbound_key, outInterface->getIPv4Address())) {
            ip->setSrcIPv4Address(nat_session->getNatIp());
            setTransportSourcePort(packet, ip, transport, nat_session->getNatPort());
        }
    }

    const pcpp::IPv4Address nextHop = dst;
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
