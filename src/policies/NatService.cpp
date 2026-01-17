#include "../../include/policies/NatService.h"
#include <arpa/inet.h>

pcpp::IPv4Layer* NatService::applyNat(
    const NatSession& session,
    pcpp::IPv4Layer* ipLayerPacket,
    pcpp::TcpLayer* tcpLayerPacket
)
{
    if (!ipLayerPacket || !tcpLayerPacket) {
        return ipLayerPacket;
    }

    const auto& flow = session.getSourceToDestinationFlow();
    const pcpp::IPv4Address srcIp = ipLayerPacket->getSrcIPv4Address();
    const pcpp::IPv4Address dstIp = ipLayerPacket->getDstIPv4Address();
    const uint16_t srcPort = ntohs(tcpLayerPacket->getTcpHeader()->portSrc);
    const uint16_t dstPort = ntohs(tcpLayerPacket->getTcpHeader()->portDst);

    if (session.isSourceNat()) {
        if (srcIp == flow.internal_ip && dstIp == flow.external_ip &&
            srcPort == flow.internal_port && dstPort == flow.external_port) {
            ipLayerPacket->setSrcIPv4Address(session.getNatIp());
            tcpLayerPacket->getTcpHeader()->portSrc = htons(session.getNatPort());
        } else if (srcIp == flow.external_ip && dstIp == session.getNatIp() &&
                   srcPort == flow.external_port && dstPort == session.getNatPort()) {
            ipLayerPacket->setDstIPv4Address(flow.internal_ip);
            tcpLayerPacket->getTcpHeader()->portDst = htons(flow.internal_port);
        }
    }

    return ipLayerPacket;
}
