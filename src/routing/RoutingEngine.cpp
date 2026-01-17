#include "../../include/routing/RoutingEngine.h"

#include <algorithm>
#include <iostream>
#include <cstring>
#include <unordered_set>

#include "pcapplusplus/EthLayer.h"
#include "pcapplusplus/ArpLayer.h"
#include "pcapplusplus/SystemUtils.h"
#include "pcapplusplus/TcpLayer.h"
#include "pcapplusplus/UdpLayer.h"
#include <arpa/inet.h>
#include "../../include/logging/Logger.h"

RoutingEngine::RoutingEngine() = default;
static std::unordered_set<uint64_t> myMacAddresses;
constexpr uint8_t kIcmpProtocol = 1;

struct TransportFlow
{
    uint16_t src_port{0};
    uint16_t dst_port{0};
    pcpp::ProtocolType protocol{pcpp::UnknownProtocol};
    bool has_ports{false};
    bool is_icmp{false};
};

TransportFlow getTransportFlow(pcpp::Packet& packet, pcpp::IPv4Layer* ipLayer)
{
    if (auto* tcp = packet.getLayerOfType<pcpp::TcpLayer>()) {
        return {
            ntohs(tcp->getTcpHeader()->portSrc),
            ntohs(tcp->getTcpHeader()->portDst),
            pcpp::TCP,
            true,
            false
        };
    }
    if (auto* udp = packet.getLayerOfType<pcpp::UdpLayer>()) {
        return {
            ntohs(udp->getUdpHeader()->portSrc),
            ntohs(udp->getUdpHeader()->portDst),
            pcpp::UDP,
            true,
            false
        };
    }

    TransportFlow flow;
    if (ipLayer) {
        flow.protocol = static_cast<pcpp::ProtocolType>(ipLayer->getIPv4Header()->protocol);
        if (ipLayer->getIPv4Header()->protocol == kIcmpProtocol) {
            auto* payload = ipLayer->getLayerPayload();
            size_t payloadSize = ipLayer->getLayerPayloadSize();
            if (payload && payloadSize >= 6) {
                auto* id_ptr = reinterpret_cast<uint16_t*>(payload + 4);
                uint16_t id = ntohs(*id_ptr);
                flow.src_port = id;
                flow.dst_port = id;
                flow.protocol = pcpp::ICMP;
                flow.has_ports = true;
                flow.is_icmp = true;
            }
        }
    }
    return flow;
}

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

void RoutingEngine::routePacket(
    pcpp::Packet& packet,
    pcpp::PcapLiveDevice* inInterface,
    RoutingTable& routing_table,
    const std::vector<NatPolicy>& nat_policies
)
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

    auto flow = getTransportFlow(packet, ip);
    SessionFlowKey key{
        ip->getSrcIPv4Address(),
        flow.src_port,
        ip->getDstIPv4Address(),
        flow.dst_port,
        flow.protocol
    };

    if (!session_table_.doesSessionExist(key)) {
        Session session(
            inInterface ? inInterface->getIPv4Address() : pcpp::IPv4Address::Zero,
            inInterface ? inInterface->getIPv4Address() : pcpp::IPv4Address::Zero,
            ip->getSrcIPv4Address(),
            flow.src_port,
            ip->getDstIPv4Address(),
            flow.dst_port
        );
        session_table_.createSession(key, std::move(session));
    }

    auto& nat_state = NatPolicy::getNatState();
    auto* nat_session = static_cast<NatSession*>(nat_state.table.findSession(key));

    if (!nat_session) {
        for (const auto& policy : nat_policies) {
            if (!policy.does_match_policy(*ip)) {
                continue;
            }
            if (policy.getNatType() == NatType::Source) {
                auto nat_port_opt = nat_state.ports.acquire_free_port_number();
                if (!nat_port_opt.has_value()) {
                    firewall::logging::Logger::warn("[NAT] No free ports available for source NAT.");
                    break;
                }
                const uint16_t nat_port = *nat_port_opt;
                const auto nat_ip = policy.getTranslatedSourceIp();

                NatSession session(
                    nat_ip,
                    ip->getSrcIPv4Address(),
                    flow.src_port,
                    ip->getDstIPv4Address(),
                    flow.dst_port,
                    nat_ip,
                    nat_port,
                    true
                );

                nat_state.table.createSession(key, session);

                SessionFlowKey reverse_key{
                    ip->getDstIPv4Address(),
                    flow.is_icmp ? nat_port : flow.dst_port,
                    nat_ip,
                    nat_port,
                    flow.protocol
                };
                nat_state.table.createSession(reverse_key, session);
                nat_session = static_cast<NatSession*>(nat_state.table.findSession(key));
                firewall::logging::Logger::info(
                    "[NAT] Created source NAT session src=" + ip->getSrcIPv4Address().toString() +
                    " dst=" + ip->getDstIPv4Address().toString() +
                    " nat_ip=" + nat_ip.toString() +
                    " nat_port=" + std::to_string(nat_port)
                );
            } else {
                const auto nat_ip = ip->getDstIPv4Address();
                const auto internal_ip = policy.getTranslatedDestinationIp();
                const uint16_t nat_port = flow.dst_port;
                const uint16_t internal_port = flow.dst_port;

                NatSession session(
                    nat_ip,
                    internal_ip,
                    internal_port,
                    ip->getSrcIPv4Address(),
                    flow.src_port,
                    nat_ip,
                    nat_port,
                    false
                );

                nat_state.table.createSession(key, session);

                SessionFlowKey reverse_key{
                    internal_ip,
                    internal_port,
                    ip->getSrcIPv4Address(),
                    flow.src_port,
                    flow.protocol
                };
                nat_state.table.createSession(reverse_key, session);
                nat_session = static_cast<NatSession*>(nat_state.table.findSession(key));
                firewall::logging::Logger::info(
                    "[NAT] Created destination NAT session src=" + ip->getSrcIPv4Address().toString() +
                    " dst=" + ip->getDstIPv4Address().toString() +
                    " internal_dst=" + internal_ip.toString()
                );
            }
            break;
        }
    }

    if (nat_session) {
        nat_service_.applyNat(*nat_session, ip);
    }

    const pcpp::IPv4Address dst = ip->getDstIPv4Address();
    auto route = routing_table.findRoute(dst);

    if (!route.has_value()) return;

    pcpp::PcapLiveDevice* outInterface = findInterfaceByName(route->interfaceName);
    if (!outInterface) return;

    auto* iphdr = ip->getIPv4Header();
    if (iphdr->timeToLive <= 1) return;
    iphdr->timeToLive -= 1;

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
