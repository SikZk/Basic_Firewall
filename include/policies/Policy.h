#ifndef BASIC_FIREWALL_POLICY_H
#define BASIC_FIREWALL_POLICY_H

#include <pcapplusplus/IpAddress.h>
#include <pcapplusplus/IPv4Layer.h>
#include <cstdint>
#include <string>

class Policy {
private:
    pcpp::IPv4Address network_from;
    pcpp::IPv4Address network_to;
    std::uint32_t     network_from_mask{0};
    std::uint32_t     network_to_mask{0};
    std::uint16_t     source_port{0};
    std::uint16_t     destination_port{0};

public:
    Policy(
        std::string     network_from_str,
        uint32_t        from_mask,
        std::string     network_to_str,
        uint32_t        to_mask,
        std::uint16_t   src_port,
        std::uint16_t   dest_port
    )
    : network_from(std::move(network_from_str)),
      network_to(std::move(network_to_str)),
      network_from_mask(from_mask),
      network_to_mask(to_mask),
      source_port(src_port),
      destination_port(dest_port)
    {}

    bool does_match_policy(const pcpp::IPv4Layer& ipv4_packet) const;
};

#endif
