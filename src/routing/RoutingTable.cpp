#include "../../include/routing/RoutingTable.h"
#include <algorithm>
#include <iostream>

namespace {
uint32_t maskToBits(const pcpp::IPv4Address& mask)
{
    uint32_t value = mask.toInt();
    uint32_t bits = 0;
    while (value) {
        bits += value & 1u;
        value >>= 1u;
    }
    return bits;
}
}

void RoutingTable::addRoute(const pcpp::IPv4Address& network,
                            const pcpp::IPv4Address& mask,
                            const pcpp::IPv4Address& gateway,
                            const std::string& iface,
                            int)
{
    routes.push_back(RouteEntry{network, mask, gateway, iface});
}

void RoutingTable::removeRoute(const pcpp::IPv4Address& network, const pcpp::IPv4Address& mask)
{
    routes.erase(
        std::remove_if(
            routes.begin(),
            routes.end(),
            [&](const RouteEntry& entry) {
                return entry.network == network && entry.netmask == mask;
            }),
        routes.end());
}

std::optional<RouteEntry> RoutingTable::findRoute(const pcpp::IPv4Address& destinationIP)
{
    std::optional<RouteEntry> best;
    uint32_t bestMask = 0;
    for (const auto& entry : routes) {
        uint32_t maskValue = entry.netmask.toInt();
        if ((destinationIP.toInt() & maskValue) == (entry.network.toInt() & maskValue)) {
            uint32_t bits = maskToBits(entry.netmask);
            if (!best.has_value() || bits > bestMask) {
                best = entry;
                bestMask = bits;
            }
        }
    }
    return best;
}

void RoutingTable::printTable() const
{
    std::cout << "[Routing] Table entries: " << routes.size() << std::endl;
    for (const auto& route : routes) {
        std::cout << "  " << route.network.toString()
                  << " mask " << route.netmask.toString()
                  << " gw " << route.gateway.toString()
                  << " iface " << route.interfaceName << std::endl;
    }
}
