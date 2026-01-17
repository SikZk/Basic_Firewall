#include "../../include/policies/NatPolicy.h"

NatState NatPolicy::nat_state(10000, 20000);

void NatPolicy::configureNatState(uint16_t port_start, uint16_t port_end)
{
    nat_state = NatState(port_start, port_end);
}

NatSession* NatPolicy::findSession(const SessionFlowKey& key)
{
    return static_cast<NatSession*>(nat_state.table.findSession(key));
}

NatSession* NatPolicy::getOrCreateSession(const SessionFlowKey& key, pcpp::IPv4Address external_ip) const
{
    return nat_state.getOrCreateSession(key, external_ip);
}

pcpp::IPv4Address NatPolicy::getTranslatedSourceIp() const
{
    return translated_source_ip;
}

pcpp::IPv4Address NatPolicy::getTranslatedDestinationIp() const
{
    return translated_destination_ip;
}
