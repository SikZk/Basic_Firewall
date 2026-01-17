#include "../../include/policies/NatService.h"
#include <arpa/inet.h>
#include <sstream>
#include "pcapplusplus/TcpLayer.h"
#include "pcapplusplus/UdpLayer.h"
#include "../../include/utils/Logger.h"

namespace {
constexpr uint8_t kIcmpProtocol = 1;

bool updateIcmpIdentifier(pcpp::IPv4Layer* ipLayerPacket, uint16_t new_id)
{
    if (!ipLayerPacket) {
        return false;
    }
    auto* payload = ipLayerPacket->getLayerPayload();
    size_t payloadSize = ipLayerPacket->getLayerPayloadSize();
    if (!payload || payloadSize < 6) {
        return false;
    }
    auto* id_ptr = reinterpret_cast<uint16_t*>(payload + 4);
    *id_ptr = htons(new_id);
    return true;
}
} // namespace

pcpp::IPv4Layer* NatService::applyNat(const NatSession& session, pcpp::IPv4Layer* ipLayerPacket)
{
    if (!ipLayerPacket) {
        return nullptr;
    }

    const auto src_ip = ipLayerPacket->getSrcIPv4Address();
    const auto dst_ip = ipLayerPacket->getDstIPv4Address();

    auto* next_layer = ipLayerPacket->getNextLayer();
    auto protocol = ipLayerPacket->getIPv4Header()->protocol;

    bool translated = false;
    std::ostringstream log_stream;

    if (session.isSourceNat()) {
        if (src_ip == session.getInternalIp() && dst_ip == session.getExternalIp()) {
            ipLayerPacket->setSrcIPv4Address(session.getNatIp());
            if (next_layer && next_layer->getProtocol() == pcpp::TCP) {
                auto* tcpLayer = static_cast<pcpp::TcpLayer*>(next_layer);
                tcpLayer->getTcpHeader()->portSrc = htons(session.getNatPort());
            } else if (next_layer && next_layer->getProtocol() == pcpp::UDP) {
                auto* udpLayer = static_cast<pcpp::UdpLayer*>(next_layer);
                udpLayer->getUdpHeader()->portSrc = htons(session.getNatPort());
            } else if (protocol == kIcmpProtocol) {
                updateIcmpIdentifier(ipLayerPacket, session.getNatPort());
            }
            translated = true;
            log_stream << "SNAT outbound "
                       << src_ip.toString() << " -> " << session.getNatIp().toString();
        } else if (src_ip == session.getExternalIp() && dst_ip == session.getNatIp()) {
            ipLayerPacket->setDstIPv4Address(session.getInternalIp());
            if (next_layer && next_layer->getProtocol() == pcpp::TCP) {
                auto* tcpLayer = static_cast<pcpp::TcpLayer*>(next_layer);
                tcpLayer->getTcpHeader()->portDst = htons(session.getInternalPort());
            } else if (next_layer && next_layer->getProtocol() == pcpp::UDP) {
                auto* udpLayer = static_cast<pcpp::UdpLayer*>(next_layer);
                udpLayer->getUdpHeader()->portDst = htons(session.getInternalPort());
            } else if (protocol == kIcmpProtocol) {
                updateIcmpIdentifier(ipLayerPacket, session.getInternalPort());
            }
            translated = true;
            log_stream << "SNAT inbound "
                       << dst_ip.toString() << " -> " << session.getInternalIp().toString();
        }
    } else {
        if (dst_ip == session.getExternalIp()) {
            ipLayerPacket->setDstIPv4Address(session.getNatIp());
            if (next_layer && next_layer->getProtocol() == pcpp::TCP) {
                auto* tcpLayer = static_cast<pcpp::TcpLayer*>(next_layer);
                tcpLayer->getTcpHeader()->portDst = htons(session.getNatPort());
            } else if (next_layer && next_layer->getProtocol() == pcpp::UDP) {
                auto* udpLayer = static_cast<pcpp::UdpLayer*>(next_layer);
                udpLayer->getUdpHeader()->portDst = htons(session.getNatPort());
            } else if (protocol == kIcmpProtocol) {
                updateIcmpIdentifier(ipLayerPacket, session.getNatPort());
            }
            translated = true;
            log_stream << "DNAT inbound "
                       << dst_ip.toString() << " -> " << session.getNatIp().toString();
        } else if (src_ip == session.getNatIp()) {
            ipLayerPacket->setSrcIPv4Address(session.getExternalIp());
            if (next_layer && next_layer->getProtocol() == pcpp::TCP) {
                auto* tcpLayer = static_cast<pcpp::TcpLayer*>(next_layer);
                tcpLayer->getTcpHeader()->portSrc = htons(session.getExternalPort());
            } else if (next_layer && next_layer->getProtocol() == pcpp::UDP) {
                auto* udpLayer = static_cast<pcpp::UdpLayer*>(next_layer);
                udpLayer->getUdpHeader()->portSrc = htons(session.getExternalPort());
            } else if (protocol == kIcmpProtocol) {
                updateIcmpIdentifier(ipLayerPacket, session.getExternalPort());
            }
            translated = true;
            log_stream << "DNAT outbound "
                       << src_ip.toString() << " -> " << session.getExternalIp().toString();
        }
    }

    if (translated) {
        Logging::logLine("[NAT]", log_stream.str());
    }
    return ipLayerPacket;
}
