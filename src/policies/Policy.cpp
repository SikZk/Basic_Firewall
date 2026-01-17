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
    const auto src = ipv4_packet.getSrcIPv4Address();
    const auto dst = ipv4_packet.getDstIPv4Address();

    if (!matchesNetwork(src, network_from, network_from_mask)) {
        return false;
    }
    if (!matchesNetwork(dst, network_to, network_to_mask)) {
        return false;
    }

    (void)source_port;
    (void)destination_port;
    return true;
}
