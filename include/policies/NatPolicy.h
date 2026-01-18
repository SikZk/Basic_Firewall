#pragma once
#include "Policy.h"
#include <string>
#include "../session/session_tables/NatSessionTable.h"

class NatPolicy : public Policy {
public:
    static NatState nat_state;

    // Use std::string instead of std::pmr::string
    NatPolicy(
            std::string network_from_str,
            uint32_t network_from_mask,
            std::string network_to_str,
            uint32_t network_to_mask,
            uint16_t source_port,
            uint16_t destination_port
    ) : Policy(network_from_str, network_from_mask, network_to_str, network_to_mask, source_port, destination_port)
    {}

    pcpp::IPv4Layer applyNat(pcpp::IPv4Layer* ipLayer);

    static void configureNatState(uint16_t port_start, uint16_t port_end);
};