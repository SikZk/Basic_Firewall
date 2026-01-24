#pragma once
#include "pcapplusplus/IPv4Layer.h"
#include "pcapplusplus/IpAddress.h"
#include <string>

/**
 * @brief Base policy with network and port matching criteria.
 */
class Policy {
public:
    /** @brief Source network base address. */
    pcpp::IPv4Address network_from;
    /** @brief Source network mask length in bits. */
    uint32_t network_from_mask;

    /** @brief Destination network base address. */
    pcpp::IPv4Address network_to;
    /** @brief Destination network mask length in bits. */
    uint32_t network_to_mask;

    /** @brief Source port filter (0 for any). */
    uint16_t source_port;
    /** @brief Destination port filter (0 for any). */
    uint16_t destination_port;

    /**
     * @brief Construct a policy with matching criteria.
     *
     * @param network_from_str Source network in dotted decimal.
     * @param network_from_mask Source CIDR mask length.
     * @param network_to_str Destination network in dotted decimal.
     * @param network_to_mask Destination CIDR mask length.
     * @param source_port Source port to match (0 for any).
     * @param destination_port Destination port to match (0 for any).
     */
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

    /**
     * @brief Virtual destructor for safe polymorphic deletion.
     */
    virtual ~Policy() = default;

    /**
     * @brief Determine if an IPv4 packet matches this policy.
     *
     * @param ipv4_packet IPv4 layer to evaluate.
     * @return True if packet matches the policy criteria.
     */
    bool does_match_policy(const pcpp::IPv4Layer& ipv4_packet) const;
};
