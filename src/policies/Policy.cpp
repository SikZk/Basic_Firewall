#include "../../include/policies/Policy.h"
#include <iostream>
#include <vector>
#include <arpa/inet.h> // For inet_pton
#include <cstring>     // For memset, memcpy

namespace {

// Robust matcher that parses IP from string to ensure correct byte order
bool matchesNetwork(const pcpp::IPv4Address& address, const pcpp::IPv4Address& network, uint32_t maskBits)
{
    if (maskBits == 0) {
        return true;
    }
    if (maskBits > 32) {
        maskBits = 32;
    }

    // Buffer for Network Byte Order bytes (Big Endian: 10.2.0.2 -> [10, 2, 0, 2])
    uint8_t addrBytes[4];
    uint8_t netBytes[4];

    // Use inet_pton to safely convert string "10.2.0.2" to raw bytes
    // This avoids reliance on toInt() endianness behavior
    if (inet_pton(AF_INET, address.toString().c_str(), addrBytes) != 1) {
        return false; // Parsing failed
    }
    if (inet_pton(AF_INET, network.toString().c_str(), netBytes) != 1) {
        return false;
    }

    // Compare byte by byte based on mask
    for (uint32_t i = 0; i < 4; ++i) {
        if (maskBits >= 8) {
            // Full byte match required (e.g. check '10' == '10')
            if (addrBytes[i] != netBytes[i]) {
                return false;
            }
            maskBits -= 8;
        } else if (maskBits > 0) {
            // Partial byte match (remainder of the mask)
            uint8_t mask = static_cast<uint8_t>(0xFF << (8 - maskBits));
            if ((addrBytes[i] & mask) != (netBytes[i] & mask)) {
                return false;
            }
            maskBits = 0;
        } else {
            // Mask exhausted, remaining bytes don't matter
            break;
        }
    }
    return true;
}

} // namespace

bool Policy::does_match_policy(const pcpp::IPv4Layer& ipv4_packet) const
{
    const auto src = ipv4_packet.getSrcIPv4Address();
    const auto dst = ipv4_packet.getDstIPv4Address();

    // Check Source Network
    if (!matchesNetwork(src, network_from, network_from_mask)) {
        return false;
    }

    // Check Destination Network
    if (!matchesNetwork(dst, network_to, network_to_mask)) {
        return false;
    }

    (void)source_port;
    (void)destination_port;

    return true;
}
