#include "../../include/policies/Policy.h"
#include <arpa/inet.h>

namespace {

bool matchesNetwork(const pcpp::IPv4Address& address, const pcpp::IPv4Address& network, uint32_t maskBits)
{
    if (maskBits == 0) {
        return true;
    }
    if (maskBits > 32) {
        maskBits = 32;
    }

    uint8_t addrBytes[4];
    uint8_t netBytes[4];

    if (inet_pton(AF_INET, address.toString().c_str(), addrBytes) != 1) {
        return false;
    }
    if (inet_pton(AF_INET, network.toString().c_str(), netBytes) != 1) {
        return false;
    }

    for (uint32_t i = 0; i < 4; ++i) {
        if (maskBits >= 8) {
            if (addrBytes[i] != netBytes[i]) {
                return false;
            }
            maskBits -= 8;
        } else if (maskBits > 0) {
            uint8_t mask = static_cast<uint8_t>(0xFF << (8 - maskBits));
            if ((addrBytes[i] & mask) != (netBytes[i] & mask)) {
                return false;
            }
            maskBits = 0;
        } else {
            break;
        }
    }
    return true;
}

}

bool Policy::does_match_policy(const pcpp::IPv4Layer& ipv4_packet) const
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
