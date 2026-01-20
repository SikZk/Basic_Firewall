#include "pcapplusplus/PcapLiveDeviceList.h"
#include "pcapplusplus/PcapLiveDevice.h"
#include "pcapplusplus/IPv4Layer.h"
#include "pcapplusplus/TcpLayer.h"
#include "pcapplusplus/IcmpLayer.h"
#include "pcapplusplus/EthLayer.h"
#include "../include/configuration/Config.h"
#include "../include/session/sessions/Session.h"
#include "../include/session/sessions/DecryptionSession.h"
#include "../include/session/sessions/NatSession.h"
#include "../include/utils.h"
#include "iostream"

#include <arpa/inet.h>
#include <pcapplusplus/Packet.h>

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

SessionFlowKey getKeyFromPacket(Packet& packet) {
    IPv4Layer* ip = packet.getLayerOfType<IPv4Layer>();
    TcpLayer* tcp = packet.getLayerOfType<TcpLayer>();
    IcmpLayer* icmp = packet.getLayerOfType<IcmpLayer>();

    SessionFlowKey key;
    if (!ip) return key;

    key.src_ip = ip->getSrcIPv4Address();
    key.dst_ip = ip->getDstIPv4Address();

    if (tcp) {
        key.protocol = pcpp::TCP;
        key.src_port = ntohs(tcp->getTcpHeader()->portSrc);
        key.dst_port = ntohs(tcp->getTcpHeader()->portDst);
    } else if (icmp) {
        key.protocol = pcpp::ICMP;
        uint16_t id = 0;
        if (icmp->getData() && icmp->getDataLen() >= 6) {
            id = ntohs(*reinterpret_cast<uint16_t*>(icmp->getData() + 4));
        }
        key.src_port = id;
        key.dst_port = id;
    } else {
        key.protocol = pcpp::PacketTrailer;
    }
    return key;
}

bool isInternalNetwork(const IPv4Address& ip) {
    return ip.toString().rfind("10.", 0) == 0;
}

bool isHttpsPacket(const TcpLayer* tcpLayer)
{
    if (!tcpLayer) {
        return false;
    }
    const auto* header = tcpLayer->getTcpHeader();
    if (!header) {
        return false;
    }
    uint16_t src_port = ntohs(header->portSrc);
    uint16_t dst_port = ntohs(header->portDst);
    return src_port == 443 || dst_port == 443;
}

// Helper to build and send a single RST packet
void sendSingleRst(
    PcapLiveDevice* inDev, 
    RoutingEngine& routingEngine, 
    NatService& natService,
    const RoutingTable& routingTable,
    pcpp::MacAddress srcMac, pcpp::MacAddress dstMac,
    pcpp::IPv4Address srcIp, pcpp::IPv4Address dstIp,
    uint16_t srcPort, uint16_t dstPort,
    uint32_t seq, uint32_t ack,
    bool setAckFlag,
    SessionFlowKey natKey // Key to check for existing NAT session
)
{
    EthLayer newEth(srcMac, dstMac, PCPP_ETHERTYPE_IP);
    IPv4Layer newIp(srcIp, dstIp);
    newIp.getIPv4Header()->timeToLive = 64;

    TcpLayer newTcp(srcPort, dstPort);
    newTcp.getTcpHeader()->sequenceNumber = seq;
    newTcp.getTcpHeader()->ackNumber = ack;
    newTcp.getTcpHeader()->rstFlag = 1;
    newTcp.getTcpHeader()->ackFlag = setAckFlag ? 1 : 0;
    newTcp.getTcpHeader()->windowSize = htons(0);

    Packet rstPacket(100);
    rstPacket.addLayer(&newEth);
    rstPacket.addLayer(&newIp);
    rstPacket.addLayer(&newTcp);

    // Apply NAT if session exists (e.g. modify SrcIP if this is Outbound acting as Client)
    if (auto* session = NatPolicy::nat_state.table.findSession(natKey)) {
        natService.applyNat(*static_cast<NatSession*>(session), rstPacket.getLayerOfType<IPv4Layer>());
    }

    rstPacket.computeCalculateFields();
    routingEngine.routePacket(rstPacket, inDev, const_cast<RoutingTable&>(routingTable));
}

void sendTcpRst(
    Packet& blockedPacket, 
    PcapLiveDevice* inDev, 
    RoutingEngine& routingEngine, 
    NatService& natService,
    const RoutingTable& routingTable
)
{
    if (!blockedPacket.isPacketOfType(TCP)) return;

    IPv4Layer* ip = blockedPacket.getLayerOfType<IPv4Layer>();
    TcpLayer* tcp = blockedPacket.getLayerOfType<TcpLayer>();
    EthLayer* eth = blockedPacket.getLayerOfType<EthLayer>();

    if (!ip || !tcp || !eth) return;

    uint32_t payloadLen = tcp->getLayerPayloadSize();
    // Logical length of the TCP segment (Payload + SYN/FIN)
    uint32_t segLen = payloadLen;
    if (tcp->getTcpHeader()->synFlag || tcp->getTcpHeader()->finFlag) {
         segLen++;
    }

    SessionFlowKey natKey = getKeyFromPacket(blockedPacket);

    // --- 1. RST to SENDER ---
    // (Termination of the connection from the side that sent the blocked packet)
    // Addressed to Sender. Seq = IncomingAck.
    {
        uint32_t seq = 0;
        uint32_t ack = 0;
        bool ackFlag = false;

        if (tcp->getTcpHeader()->ackFlag) {
            seq = tcp->getTcpHeader()->ackNumber;
            // No need to set ACK implies AckNum=0, AckFlag=0
        } else {
            seq = 0;
            ack = htonl(ntohl(tcp->getTcpHeader()->sequenceNumber) + segLen);
            ackFlag = true;
        }

        sendSingleRst(
            inDev, routingEngine, natService, routingTable,
            eth->getDestMac(), eth->getSourceMac(),       // Swap MAC
            ip->getDstIPv4Address(), ip->getSrcIPv4Address(), // Swap IP
            ntohs(tcp->getTcpHeader()->portDst), ntohs(tcp->getTcpHeader()->portSrc), // Swap Port
            seq, ack, ackFlag,
            natKey // Use same NAT key (Inbound packet -> Inbound usage in NAT)
        );
    }
    
    // --- 2. RST to RECEIVER ---
    // (Termination of the connection from the side that was supposed to receive the packet)
    // Addressed to Receiver. Seq = IncomingSeq (Original).
    // This looks like the packet we blocked, but with RST flag.
    // Important: NAT logic.
    // If blocked packet was Server->Client (Src=8.8.8.8, Dst=104...), we want to send to Client (Dst=10...).
    // rstPacket constructed here has Src=Server, Dst=104...
    // When passed to routePacket, it behaves like an Inbound packet.
    // NAT Service should DNAT it to Client.
    {
        uint32_t seq = tcp->getTcpHeader()->sequenceNumber;
        uint32_t ack = tcp->getTcpHeader()->ackNumber;
        bool ackFlag = (tcp->getTcpHeader()->ackFlag == 1);

        sendSingleRst(
            inDev, routingEngine, natService, routingTable,
            eth->getSourceMac(), eth->getDestMac(),       // Keep Direction (Sender -> Receiver)
            ip->getSrcIPv4Address(), ip->getDstIPv4Address(), // Keep Direction
            ntohs(tcp->getTcpHeader()->portSrc), ntohs(tcp->getTcpHeader()->portDst), // Keep Direction
            seq, ack, ackFlag,
            natKey 
        );
    }

    std::cout << "[SECURITY] Sent Dual TCP RST to terminate connection." << std::endl;
}

