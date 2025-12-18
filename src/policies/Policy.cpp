#include <string>
#include <arpa/inet.h>
#include <utility>
#include <pcapplusplus/IPv4Layer.h>
#include <pcapplusplus/TcpLayer.h>
#include "../../include/policies/Policy.h"

namespace {
bool matchNetwork(const pcpp::IPAddress& address, const pcpp::IPv4Network& network) {
    if (!address.isIPv4()) return false;
    std::string repr = network.toString();
    auto slash = repr.find('/');
    pcpp::IPv4Address net_addr(repr.substr(0, slash));
    uint8_t prefix = 32;
    if (slash != std::string::npos) {
        prefix = static_cast<uint8_t>(std::stoi(repr.substr(slash + 1)));
    }
    return address.getIPv4().matchSubnet(net_addr, prefix);
}
}

bool Policy::does_match_policy(pcpp::IPv4Layer ipv4_packet) {
    bool src_ip_match = matchNetwork(ipv4_packet.getSrcIPAddress(), network_from);
    bool dst_ip_match = matchNetwork(ipv4_packet.getDstIPAddress(), network_to);

    auto* tcpLayer = ipv4_packet.getLayerOfType<pcpp::TcpLayer>();
    uint16_t pkt_src_port = tcpLayer ? ntohs(tcpLayer->getTcpHeader()->portSrc) : 0;
    uint16_t pkt_dst_port = tcpLayer ? ntohs(tcpLayer->getTcpHeader()->portDst) : 0;
    bool src_port_match = source_port == 0 || source_port == pkt_src_port;
    bool dst_port_match = destination_port == 0 || destination_port == pkt_dst_port;

    return src_ip_match && dst_ip_match && src_port_match && dst_port_match;
}
