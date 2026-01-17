#include "../../include/policies/NatService.h"
#include <iostream>
#include <pcapplusplus/TcpLayer.h>
#include <pcapplusplus/UdpLayer.h>
#include <arpa/inet.h>

pcpp::IPv4Layer* NatService::applyNat(NatSession session, pcpp::IPv4Layer* ipLayerPacket)
{
    if (!ipLayerPacket) {
        return ipLayerPacket;
    }

    auto* nextLayer = ipLayerPacket->getNextLayer();
    pcpp::TcpLayer* tcpLayer = nullptr;
    pcpp::UdpLayer* udpLayer = nullptr;
    if (nextLayer) {
        if (nextLayer->getProtocol() == pcpp::TCP) {
            tcpLayer = static_cast<pcpp::TcpLayer*>(nextLayer);
        } else if (nextLayer->getProtocol() == pcpp::UDP) {
            udpLayer = static_cast<pcpp::UdpLayer*>(nextLayer);
        }
    }

    const auto& forward_flow = session.getSourceToDestinationFlow();
    bool outbound = ipLayerPacket->getSrcIPv4Address() == forward_flow.internal_ip &&
                    ipLayerPacket->getDstIPv4Address() == forward_flow.external_ip;
    bool inbound = ipLayerPacket->getDstIPv4Address() == session.getNatIp() &&
                   ipLayerPacket->getSrcIPv4Address() == forward_flow.external_ip;

    if (session.isSourceNat() && outbound) {
        ipLayerPacket->setSrcIPv4Address(session.getNatIp());
        if (tcpLayer) {
            tcpLayer->getTcpHeader()->portSrc = htons(session.getNatPort());
        } else if (udpLayer) {
            udpLayer->getUdpHeader()->portSrc = htons(session.getNatPort());
        }
        std::cout << "[NAT] Applied source NAT to " << session.getNatIp().toString() << std::endl;
        return ipLayerPacket;
    }

    if (session.isSourceNat() && inbound) {
        ipLayerPacket->setDstIPv4Address(forward_flow.internal_ip);
        if (tcpLayer) {
            tcpLayer->getTcpHeader()->portDst = htons(forward_flow.internal_port);
        } else if (udpLayer) {
            udpLayer->getUdpHeader()->portDst = htons(forward_flow.internal_port);
        }
        std::cout << "[NAT] Applied reverse NAT to " << forward_flow.internal_ip.toString() << std::endl;
        return ipLayerPacket;
    }

    std::cout << "[NAT] No translation applied." << std::endl;
    return ipLayerPacket;
}
