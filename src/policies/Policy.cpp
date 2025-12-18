#include <string>
#include <arpa/inet.h>
#include <utility>
#include <pcapplusplus/IPv4Layer.h>
#include <pcapplusplus/TcpLayer.h>
#include "../../include/policies/Policy.h"

namespace {
uint32_t maskFromPrefix(uint8_t prefixLen) {
    if (prefixLen == 0) return 0;
    return htonl(0xFFFFFFFFu << (32 - prefixLen));
}

bool matchNetwork(const pcpp::IPAddress& address, const pcpp::IPv4Address& network, uint8_t prefixLen) {
    if (!address.isIPv4()) return false;
    uint32_t mask = maskFromPrefix(prefixLen);
    return (address.getIPv4().toInt() & mask) == (network.toInt() & mask);
}
} // namespace

bool Policy::does_match_policy(pcpp::IPv4Layer ipv4_packet) {
    bool src_ip_match = matchNetwork(ipv4_packet.getSrcIPAddress(), network_from_base, network_from_prefix);
    bool dst_ip_match = matchNetwork(ipv4_packet.getDstIPAddress(), network_to_base, network_to_prefix);

    pcpp::TcpLayer* tcpLayer = nullptr;
    for (auto* layer = ipv4_packet.getNextLayer(); layer != nullptr; layer = layer->getNextLayer()) {
        if (layer->getProtocol() == pcpp::TCP) {
            tcpLayer = static_cast<pcpp::TcpLayer*>(layer);
            break;
        }
    }

    uint16_t pkt_src_port = tcpLayer ? ntohs(tcpLayer->getTcpHeader()->portSrc) : 0;
    uint16_t pkt_dst_port = tcpLayer ? ntohs(tcpLayer->getTcpHeader()->portDst) : 0;
    bool src_port_match = source_port == 0 || source_port == pkt_src_port;
    bool dst_port_match = destination_port == 0 || destination_port == pkt_dst_port;

    return src_ip_match && dst_ip_match && src_port_match && dst_port_match;
}
