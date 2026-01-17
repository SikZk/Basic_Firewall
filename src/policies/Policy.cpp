#include "../../include/policies/Policy.h"

namespace {
bool matchesNetwork(const pcpp::IPv4Address& address, const pcpp::IPv4Address& network, uint32_t maskBits)
{
    if (maskBits == 0) {
        return true;
    }
    uint32_t mask = maskBits >= 32 ? 0xFFFFFFFFu : (0xFFFFFFFFu << (32 - maskBits));
    return (address.toInt() & mask) == (network.toInt() & mask);
}
} // namespace

bool Policy::does_match_policy(pcpp::IPv4Layer ipv4_packet)
{
    return matchesFlow(
        ipv4_packet.getSrcIPv4Address(),
        ipv4_packet.getDstIPv4Address(),
        0,
        0
    );
}

bool Policy::matchesFlow(
    const pcpp::IPv4Address& source_ip,
    const pcpp::IPv4Address& destination_ip,
    std::uint16_t source_port_value,
    std::uint16_t destination_port_value
) const
{
    if (!matchesNetwork(source_ip, network_from, network_from_mask)) {
        return false;
    }
    if (!matchesNetwork(destination_ip, network_to, network_to_mask)) {
        return false;
    }

    if (source_port != 0 && source_port != source_port_value) {
        return false;
    }
    if (destination_port != 0 && destination_port != destination_port_value) {
        return false;
    }
    return true;
}
