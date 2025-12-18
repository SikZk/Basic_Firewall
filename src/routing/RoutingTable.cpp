#include <algorithm>
#include <arpa/inet.h>
#include "../../include/routing/RoutingTable.h"

namespace {
uint8_t maskToPrefix(const pcpp::IPv4Address& mask) {
    uint32_t value = ntohl(mask.toInt());
    uint8_t count = 0;
    while (value & 0x80000000) {
        ++count;
        value <<= 1U;
    }
    return count;
}

bool addressMatches(const pcpp::IPv4Address& address, const pcpp::IPv4Address& network, const pcpp::IPv4Address& mask) {
    uint32_t maskValue = mask.toInt();
    return (address.toInt() & maskValue) == (network.toInt() & maskValue);
}
}

void RoutingTable::addRoute(
    const pcpp::IPv4Address& network,
    const pcpp::IPv4Address& mask,
    const pcpp::IPv4Address& gateway,
    const std::string& iface,
    int /*metric*/
) {
    routes.push_back({network, mask, gateway, iface});
}

void RoutingTable::removeRoute(const pcpp::IPv4Address& network, const pcpp::IPv4Address& mask) {
    routes.erase(
        std::remove_if(
            routes.begin(),
            routes.end(),
            [&](const RouteEntry& entry) { return entry.network == network && entry.netmask == mask; }
        ),
        routes.end()
    );
}

std::optional<RouteEntry> RoutingTable::findRoute(const pcpp::IPv4Address& destinationIP) {
    for (const auto& route : routes) {
        if (addressMatches(destinationIP, route.network, route.netmask)) {
            return route;
        }
    }
    return std::nullopt;
}

void RoutingTable::printTable() const {
    for (const auto& route : routes) {
        std::cout << route.network.toString() << "/" << route.netmask.toString()
                  << " via " << route.gateway.toString()
                  << " dev " << route.interfaceName << std::endl;
    }
}
