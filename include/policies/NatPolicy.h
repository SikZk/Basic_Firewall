//
// Created by mikolaj on 11/5/25.
//

#ifndef BASIC_FIREWALL_NAT_POLICY_H
#define BASIC_FIREWALL_NAT_POLICY_H

#include <boost/unordered_set.hpp>
#include <vector>
#include <pcapplusplus/RawPacket.h>
#include "../session/session_tables/NatSessionTable.h"


class NatPolicy : public Policy {
    private:
        static NatState nat_state;
        pcpp::IPv4Address translated_source_ip;
        pcpp::IPv4Address translated_destination_ip;

    public:
        NatPolicy(
            std::pmr::string network_from_str,
            uint32_t         from_mask,
            std::pmr::string network_to_str,
            uint32_t         to_mask,
            std::uint16_t    src_port,
            std::uint16_t    dest_port
        ) : Policy(
            std::move(network_from_str),
            from_mask,
            std::move(network_to_str),
            to_mask,
            src_port,
            dest_port
        )
        { };
        static void configureNatState(uint16_t port_start, uint16_t port_end);

        pcpp::IPv4Layer applyNat(pcpp::IPv4Layer* ipLayer);

};

#endif