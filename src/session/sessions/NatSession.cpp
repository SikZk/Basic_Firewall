#include "../../../include/session/sessions/NatSession.h"

NatSession::NatSession(
    pcpp::IPv4Address source_ip,
    uint16_t source_port,
    pcpp::IPv4Address destination_ip,
    uint16_t destination_port,
    pcpp::IPv4Address nat_ip,
    uint16_t nat_port,
    bool is_source_nat,
    bool is_destination_nat
)
    : Session(
        nat_ip,
        nat_ip,
        source_ip,
        source_port,
        destination_ip,
        destination_port
    ),
    nat_ip(nat_ip),
    nat_port(nat_port),
    source_nat(is_source_nat),
    destination_nat(is_destination_nat)
{
}

const pcpp::IPv4Address& NatSession::getNatIp() const
{
    return nat_ip;
}

uint16_t NatSession::getNatPort() const
{
    return nat_port;
}

bool NatSession::isSourceNat() const
{
    return source_nat;
}

bool NatSession::isDestinationNat() const
{
    return destination_nat;
}
