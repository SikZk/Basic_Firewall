#pragma once
#include "Policy.h"
#include <string>
#include "../session/session_tables/NatSessionTable.h"

/**
 * @brief Policy for applying network address translation.
 */
class NatPolicy : public Policy {
public:
    /** @brief Shared NAT state for managing sessions/ports. */
    static NatState nat_state;

    /**
     * @brief Construct a NAT policy with network/port criteria.
     *
     * @param network_from_str Source network in dotted decimal.
     * @param network_from_mask Source CIDR mask length.
     * @param network_to_str Destination network in dotted decimal.
     * @param network_to_mask Destination CIDR mask length.
     * @param source_port Source port to match (0 for any).
     * @param destination_port Destination port to match (0 for any).
     */
    NatPolicy(
        std::string network_from_str,
        uint32_t network_from_mask,
        std::string network_to_str,
        uint32_t network_to_mask,
        uint16_t source_port,
        uint16_t destination_port
    ) : Policy(network_from_str, network_from_mask, network_to_str, network_to_mask, source_port, destination_port)
    {}

    /**
     * @brief Apply NAT translation to an IPv4 packet.
     *
     * @param ipLayer Packet layer to modify.
     * @return Translated IPv4 layer.
     */
    pcpp::IPv4Layer applyNat(pcpp::IPv4Layer* ipLayer);

    /**
     * @brief Configure the NAT port pool.
     *
     * @param port_start First port in the pool.
     * @param port_end Last port in the pool.
     */
    static void configureNatState(uint16_t port_start, uint16_t port_end);
};
