#ifndef BASIC_FIREWALL_NAT_POLICY_H
#define BASIC_FIREWALL_NAT_POLICY_H

#include <vector>
#include <string>

#include "Policy.h"
#include "../session/session_tables/NatSessionTable.h"

enum class NatType {
    Source,
    Destination
};

class NatPolicy : public Policy {
private:
    static NatState nat_state;
    NatType nat_type{NatType::Source};
    pcpp::IPv4Address translated_source_ip;
    pcpp::IPv4Address translated_destination_ip;

public:
    NatPolicy(
        std::string      network_from_str,
        uint32_t         from_mask,
        std::string      network_to_str,
        uint32_t         to_mask,
        std::uint16_t    src_port,
        std::uint16_t    dest_port,
        NatType          type = NatType::Source,
        std::string      translated_source_ip_str = "0.0.0.0",
        std::string      translated_destination_ip_str = "0.0.0.0"
    )
    : Policy(
        std::move(network_from_str),
        from_mask,
        std::move(network_to_str),
        to_mask,
        src_port,
        dest_port
    ),
      nat_type(type),
      translated_source_ip(std::move(translated_source_ip_str)),
      translated_destination_ip(std::move(translated_destination_ip_str))
    {}

    static void configureNatState(uint16_t port_start, uint16_t port_end);
    static NatState& getNatState();

    NatType getNatType() const;
    pcpp::IPv4Address getTranslatedSourceIp() const;
    pcpp::IPv4Address getTranslatedDestinationIp() const;
};

#endif
