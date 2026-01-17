#include "../../include/policies/NatPolicy.h"
#include <iostream>

NatState NatPolicy::nat_state(10000, 20000);

void NatPolicy::configureNatState(uint16_t port_start, uint16_t port_end)
{
    nat_state = NatState(port_start, port_end);
}

std::optional<uint16_t> NatPolicy::acquirePort()
{
    return nat_state.ports.acquire_free_port_number();
}

void NatPolicy::releasePort(uint16_t port)
{
    nat_state.ports.release_port(port);
}

bool NatPolicy::doesMatchSession(const Session& session) const
{
    const auto& flow = session.getSourceToDestinationFlow();
    return matchesFlow(
        flow.internal_ip,
        flow.external_ip,
        flow.internal_port,
        flow.external_port
    );
}

bool NatPolicy::isSourceNat() const
{
    return source_nat;
}

bool NatPolicy::isDestinationNat() const
{
    return destination_nat;
}

bool NatPolicy::isNatEnabled() const
{
    return source_nat || destination_nat;
}

const pcpp::IPv4Address& NatPolicy::getTranslatedSourceIp() const
{
    return translated_source_ip;
}

const pcpp::IPv4Address& NatPolicy::getTranslatedDestinationIp() const
{
    return translated_destination_ip;
}

pcpp::IPv4Layer NatPolicy::applyNat(pcpp::IPv4Layer* ipLayer)
{
    std::cout << "[NAT] No-op NAT applied." << std::endl;
    return *ipLayer;
}
