#include "../../include/policies/NatService.h"
#include <pcapplusplus/TcpLayer.h>
#include <pcapplusplus/UdpLayer.h>
#include <pcapplusplus/IcmpLayer.h>
#include <pcapplusplus/Packet.h>
#include <pcapplusplus/IPv4Layer.h>
#include <iostream>
#include <cstring>
#include <pcapplusplus/SystemUtils.h>

pcpp::IPv4Layer* NatService::applyNat(NatSession session, pcpp::IPv4Layer* ipLayerPacket)
{
    const bool isOutbound = (ipLayerPacket->getSrcIPv4Address() == session.getSourceToDestinationFlow().internal_ip);
    auto* nextLayer = ipLayerPacket->getNextLayer();

    if (isOutbound) {
        const pcpp::IPv4Address newSrcIp = session.getDestinationToSourceFlow().external_ip;
        const uint16_t newSrcPort = session.getDestinationToSourceFlow().external_port;
        ipLayerPacket->setSrcIPv4Address(newSrcIp);
        ipLayerPacket->getIPv4Header()->headerChecksum = 0;
        ipLayerPacket->computeCalculateFields();
        if (nextLayer) {
            if (auto* tcp = dynamic_cast<pcpp::TcpLayer*>(nextLayer)) {
                tcp->getTcpHeader()->portSrc = pcpp::hostToNet16(newSrcPort);
                tcp->getTcpHeader()->headerChecksum = 0;
                tcp->computeCalculateFields();
            }
            else if (auto* udp = dynamic_cast<pcpp::UdpLayer*>(nextLayer)) {
                udp->getUdpHeader()->portSrc = pcpp::hostToNet16(newSrcPort);
                udp->getUdpHeader()->headerChecksum = 0;
                udp->computeCalculateFields();
            }
            else if (auto* icmp = dynamic_cast<pcpp::IcmpLayer*>(nextLayer)) {
                uint8_t* data = icmp->getData();
                if (data && icmp->getDataLen() >= 6) {
                    uint16_t* id_ptr = reinterpret_cast<uint16_t*>(data + 4);
                    *id_ptr = pcpp::hostToNet16(newSrcPort);
                    icmp->getIcmpHeader()->checksum = 0;
                    icmp->computeCalculateFields();
                }
            }
        }
    }
    else {
        const pcpp::IPv4Address originalClientIp = session.getSourceToDestinationFlow().internal_ip;
        const uint16_t originalClientPort = session.getSourceToDestinationFlow().internal_port;

        ipLayerPacket->setDstIPv4Address(originalClientIp);
        ipLayerPacket->getIPv4Header()->headerChecksum = 0;
        ipLayerPacket->computeCalculateFields();

        if (nextLayer) {
            if (auto* tcp = dynamic_cast<pcpp::TcpLayer*>(nextLayer)) {
                tcp->getTcpHeader()->portDst = pcpp::hostToNet16(originalClientPort);
                tcp->getTcpHeader()->headerChecksum = 0;
                tcp->computeCalculateFields();
            }
            else if (auto* udp = dynamic_cast<pcpp::UdpLayer*>(nextLayer)) {
                udp->getUdpHeader()->portDst = pcpp::hostToNet16(originalClientPort);
                udp->getUdpHeader()->headerChecksum = 0;
                udp->computeCalculateFields();
            }
            else if (auto* icmp = dynamic_cast<pcpp::IcmpLayer*>(nextLayer)) {
                uint8_t* data = icmp->getData();
                if (data && icmp->getDataLen() >= 6) {
                    uint16_t* id_ptr = reinterpret_cast<uint16_t*>(data + 4);
                    *id_ptr = pcpp::hostToNet16(originalClientPort);
                    icmp->getIcmpHeader()->checksum = 0;
                    icmp->computeCalculateFields();
                }
            }
        }
    }

    return ipLayerPacket;
}
