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
    ),
    internal_ip_(source_ip),
    internal_port_(source_port),
    external_ip_(destination_ip),
    external_port_(destination_port),
    nat_ip_(nat_ip),
    nat_port_(nat_port),
    is_source_nat_(is_source_nat)
{
}

pcpp::IPv4Address NatSession::getInternalIp() const
{
    return internal_ip_;
}

uint16_t NatSession::getInternalPort() const
{
    return internal_port_;
}

pcpp::IPv4Address NatSession::getExternalIp() const
{
    return external_ip_;
}

uint16_t NatSession::getExternalPort() const
{
    return external_port_;
}

pcpp::IPv4Address NatSession::getNatIp() const
{
    return nat_ip_;
}

uint16_t NatSession::getNatPort() const
{
    return nat_port_;
}

bool NatSession::isSourceNat() const
{
    return is_source_nat_;
}
