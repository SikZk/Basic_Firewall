//
// Created by mikolaj on 11/5/25.
//

#ifndef BASIC_FIREWALL_NAT_POLICY_H
#define BASIC_FIREWALL_NAT_POLICY_H

#include <boost/unordered_set.hpp>
#include <vector>
#include <pcapplusplus/RawPacket.h>
#include <optional>

#include "Policy.h"
#include "../session/session_tables/NatSessionTable.h"


class NatPolicy : public Policy {
    private:
        static NatState nat_state;
        pcpp::IPv4Address translated_source_ip;
        pcpp::IPv4Address translated_destination_ip;
        bool source_nat{false};
        bool destination_nat{false};

    public:
        NatPolicy(
            std::pmr::string network_from_str,
            uint32_t         from_mask,
            std::pmr::string network_to_str,
            uint32_t         to_mask,
            std::uint16_t    src_port,
            std::uint16_t    dest_port,
            std::pmr::string translated_source_ip_str = "0.0.0.0",
            std::pmr::string translated_destination_ip_str = "0.0.0.0",
            bool             source_nat = false,
            bool             destination_nat = false
        ) : Policy(
            std::move(network_from_str),
            from_mask,
            std::move(network_to_str),
            to_mask,
            src_port,
            dest_port
        ),
        translated_source_ip(std::string(translated_source_ip_str)),
        translated_destination_ip(std::string(translated_destination_ip_str)),
        source_nat(source_nat),
        destination_nat(destination_nat)
        { };
        static void configureNatState(uint16_t port_start, uint16_t port_end);
        static std::optional<uint16_t> acquirePort();
        static void releasePort(uint16_t port);

        bool doesMatchSession(const Session& session) const;
        bool isSourceNat() const;
        bool isDestinationNat() const;
        bool isNatEnabled() const;
        const pcpp::IPv4Address& getTranslatedSourceIp() const;
        const pcpp::IPv4Address& getTranslatedDestinationIp() const;
        pcpp::IPv4Layer applyNat(pcpp::IPv4Layer* ipLayer);

};

#endif
