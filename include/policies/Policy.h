#pragma once
#include "pcapplusplus/IPv4Layer.h"
#include "pcapplusplus/IpAddress.h"
#include <string>

class Policy {
public:
    pcpp::IPv4Address network_from;
    uint32_t network_from_mask;

    pcpp::IPv4Address network_to;
    uint32_t network_to_mask;

    uint16_t source_port;
    uint16_t destination_port;

    // Use std::string instead of std::pmr::string
    Policy(
        std::string network_from_str,
        uint32_t network_from_mask,
        std::string network_to_str,
        uint32_t network_to_mask,
        uint16_t source_port,
        uint16_t destination_port
    ) : network_from(network_from_str),
        network_from_mask(network_from_mask),
        network_to(network_to_str),
        network_to_mask(network_to_mask),
        source_port(source_port),
        destination_port(destination_port)
    {}

    virtual ~Policy() = default;

    bool does_match_policy(const pcpp::IPv4Layer& ipv4_packet) const;
};
