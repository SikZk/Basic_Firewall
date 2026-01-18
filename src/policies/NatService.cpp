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
    // 1. Sprawdź kierunek
    bool isOutbound = (ipLayerPacket->getSrcIPv4Address() == session.getSourceToDestinationFlow().internal_ip);
    pcpp::Layer* nextLayer = ipLayerPacket->getNextLayer();

    if (isOutbound) {
        // --- OUTBOUND (SNAT) ---
        // Zmieniamy Src IP na Publiczne IP (192.168.1.29)
        pcpp::IPv4Address newSrcIp = session.getDestinationToSourceFlow().external_ip;
        uint16_t newSrcPort = session.getDestinationToSourceFlow().external_port;

        // KROK 1: Zmiana IP
        ipLayerPacket->setSrcIPv4Address(newSrcIp);

        // KROK 2: Wymuszenie przeliczenia sumy IP TERAZ, zanim dotkniemy TCP
        ipLayerPacket->getIPv4Header()->headerChecksum = 0;
        ipLayerPacket->computeCalculateFields();

        // KROK 3: Aktualizacja warstwy transportowej (TCP/UDP/ICMP)
        if (nextLayer) {
            if (auto* tcp = dynamic_cast<pcpp::TcpLayer*>(nextLayer)) {
                // Zmiana portu
                tcp->getTcpHeader()->portSrc = pcpp::hostToNet16(newSrcPort);

                // CRITICAL FIX: Ręczne zerowanie i wymuszenie sumy
                tcp->getTcpHeader()->headerChecksum = 0;

                // To jest kluczowe: to wywołanie musi widzieć już zmienione IP w warstwie niżej
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
        // --- INBOUND (Reverse NAT) ---
        pcpp::IPv4Address originalClientIp = session.getSourceToDestinationFlow().internal_ip;
        uint16_t originalClientPort = session.getSourceToDestinationFlow().internal_port;

        ipLayerPacket->setDstIPv4Address(originalClientIp);

        // Przelicz IP checksum od razu
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