#include "pcapplusplus/PcapLiveDeviceList.h"
#include "pcapplusplus/PcapLiveDevice.h"
#include "pcapplusplus/IPv4Layer.h"
#include "pcapplusplus/TcpLayer.h"
#include "../include/configuration/Config.h"
#include "../include/session/sessions/Session.h"
#include "../include/session/sessions/DecryptionSession.h"
#include "../include/session/sessions/NatSession.h"
#include "utils.h"
#include <arpa/inet.h>
#include <iostream>
#include "pcapplusplus/EthLayer.h"
#include "pcapplusplus/IPv4Layer.h"
#include "pcapplusplus/TcpLayer.h"
#include "pcapplusplus/Packet.h"

void sendTcpRst(pcpp::Packet& packet, pcpp::PcapLiveDevice* outInterface) {
    if (!outInterface) return;

    pcpp::EthLayer* ethLayer = packet.getLayerOfType<pcpp::EthLayer>();
    pcpp::IPv4Layer* ipLayer = packet.getLayerOfType<pcpp::IPv4Layer>();
    pcpp::TcpLayer* tcpLayer = packet.getLayerOfType<pcpp::TcpLayer>();

    if (!ethLayer || !ipLayer || !tcpLayer) return;

    // Create a new packet
    pcpp::Packet rstPacket;

    // 1. Ethernet Layer - swap src/dst
    pcpp::EthLayer newEthLayer(outInterface->getMacAddress(), ethLayer->getSourceMac());
    rstPacket.addLayer(&newEthLayer);

    // 2. IPv4 Layer - swap src/dst
    pcpp::IPv4Layer newIpLayer(ipLayer->getDstIPv4Address(), ipLayer->getSrcIPv4Address());
    newIpLayer.getIPv4Header()->timeToLive = 64;
    rstPacket.addLayer(&newIpLayer);

    // 3. TCP Layer - swap ports, set RST flag
    // Sequence number logic for RST:
    // If ACK is set in original: Seq = Ack, Ack = 0 (RST usually doesn't need ACK, but RST+ACK is also common. RST alone is fine often.)
    // If ACK is NOT set (e.g. SYN): Seq = 0, Ack = Seq + Len (or +1 for SYN) + Ack flag.
    // For simplicity and effectiveness in blocking:
    // We send RST+ACK. Seq = Received Ack. Ack = Received Seq + Payload Len + Flags(SYN/FIN=1 else 0)

    uint32_t receivedSeq = ntohl(tcpLayer->getTcpHeader()->sequenceNumber);
    uint32_t receivedAck = ntohl(tcpLayer->getTcpHeader()->ackNumber);
    uint32_t receivedPayloadLen = tcpLayer->getLayerPayloadSize();
    
    // Calculate new Seq and Ack
    uint32_t newSeq = 0;
    uint32_t newAck = 0;
    
    // If the blocked packet has ACK, our RST should use that ACK as SEQ.
    if (tcpLayer->getTcpHeader()->ackFlag) {
        newSeq = receivedAck;
    } else {
        newSeq = 0; 
    }

    // We need to ACK whatever they sent us so they accept the RST
    // Increase Ack by 1 if SYN or FIN was set, plus payload length
    uint32_t lenToAdd = receivedPayloadLen;
    if (tcpLayer->getTcpHeader()->synFlag || tcpLayer->getTcpHeader()->finFlag) {
        lenToAdd += 1;
    }
    newAck = receivedSeq + lenToAdd;


    pcpp::TcpLayer newTcpLayer(ntohs(tcpLayer->getTcpHeader()->portDst), ntohs(tcpLayer->getTcpHeader()->portSrc));
    newTcpLayer.getTcpHeader()->rstFlag = 1;
    newTcpLayer.getTcpHeader()->ackFlag = 1;
    newTcpLayer.getTcpHeader()->sequenceNumber = htonl(newSeq);
    newTcpLayer.getTcpHeader()->ackNumber = htonl(newAck);
    newTcpLayer.getTcpHeader()->windowSize = htons(0); // Window 0 usually for RST

    rstPacket.addLayer(&newTcpLayer);

    rstPacket.computeCalculateFields();

    if (!outInterface->sendPacket(&rstPacket)) {
        std::cerr << "[RST] Failed to send RST packet" << std::endl;
    } else {
        std::cout << "[RST] Sent TCP Reset to " << ipLayer->getSrcIPv4Address().toString() << std::endl;
    }
}

using namespace pcpp;

SessionFlowKey getSessionFlowKey(
    const IPv4Layer* ipLayerPacket,
    const TcpLayer* tcpLayerPacket
)
{
    return Session::generateSessionFlowKey(
        ipLayerPacket->getSrcIPv4Address(),
        ntohs(tcpLayerPacket->getTcpHeader()->portSrc),
        ipLayerPacket->getDstIPv4Address(),
        ntohs(tcpLayerPacket->getTcpHeader()->portDst)
    );
}

Session* createOrGetSession(
    SessionTable &sessionTable,
    const SessionFlowKey& key,
    const IPv4Layer* ipLayerPacket,
    const TcpLayer* tcpLayerPacket,
    PcapLiveDevice* captureInterface
)
{
    if (Session* existing = sessionTable.findSession(key)) {
        return existing;
    }
    Session session(
        captureInterface->getIPv4Address(),
        captureInterface->getIPv4Address(),
        ipLayerPacket->getSrcIPv4Address(),
        ntohs(tcpLayerPacket->getTcpHeader()->portSrc),
        ipLayerPacket->getDstIPv4Address(),
        ntohs(tcpLayerPacket->getTcpHeader()->portDst)
    );
    return &sessionTable.createSession(key, std::move(session));
}

DecryptionSession* createOrGetDecryptionSession(
    DecryptionSessionTable &decryptionSessionTable,
    const SessionFlowKey& key,
    Session* session,
    DecryptionProfile
)
{
    if (auto* existing = decryptionSessionTable.findSession(key)) {
        return static_cast<DecryptionSession*>(existing);
    }
    DecryptionSession new_session(
        session->getSourceToDestinationFlow().internal_ip,
        session->getSourceToDestinationFlow().internal_ip,
        session->getSourceToDestinationFlow().internal_port,
        session->getSourceToDestinationFlow().external_ip,
        session->getSourceToDestinationFlow().external_port
    );
    return static_cast<DecryptionSession*>(&decryptionSessionTable.createSession(key, std::move(new_session)));
}

NatSession createOrGetNatSession(
    NatSessionTable &natSessionTable,
    const SessionFlowKey& key,
    Session* session,
    NatPolicy
)
{
    if (auto* existing = natSessionTable.findSession(key)) {
        return *static_cast<NatSession*>(existing);
    }
    NatSession new_session(
        session->getSourceToDestinationFlow().internal_ip,
        session->getSourceToDestinationFlow().internal_ip,
        session->getSourceToDestinationFlow().internal_port,
        session->getSourceToDestinationFlow().external_ip,
        session->getSourceToDestinationFlow().external_port,
        session->getSourceToDestinationFlow().external_ip,
        session->getSourceToDestinationFlow().external_port,
        true
    );
    return static_cast<NatSession&>(natSessionTable.createSession(key, std::move(new_session)));
}

bool isNotEncryptedSession(Session*)
{
    return true;
}
