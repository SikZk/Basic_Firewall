#include "../../../include/session/sessions/NatSession.h"

NatSession::NatSession(
    pcpp::IPv4Address firewall_interface_ip,
    pcpp::IPv4Address source_ip,
    uint16_t source_port,
    pcpp::IPv4Address destination_ip,
    uint16_t destination_port,
    pcpp::IPv4Address nat_ip,
    uint16_t nat_port,
    bool is_source_nat
)
    : Session(
        firewall_interface_ip,
        firewall_interface_ip,
        source_ip,
        source_port,
        destination_ip,
        destination_port
    )
{
    (void)is_source_nat;

    destination_to_source.external_ip = nat_ip;
    destination_to_source.external_port = nat_port;
}
