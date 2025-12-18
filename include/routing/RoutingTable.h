//
// Created by mikolaj on 11/5/25.
//

#ifndef BASIC_FIREWALL_ROUTING_TABLE_H
#define BASIC_FIREWALL_ROUTING_TABLE_H
#include <optional>
#include <vector>
#include <string>
#include <pcapplusplus/IpAddress.h>
#include <iostream>
struct RouteEntry {
    pcpp::IPv4Address network;
    pcpp::IPv4Address netmask;
    pcpp::IPv4Address gateway;
    std::string interfaceName;
};

class RoutingTable {
    private:
        std::vector<RouteEntry> routes;

    public:
        RoutingTable() = default;

        void addRoute(const pcpp::IPv4Address& network,
                  const pcpp::IPv4Address& mask,
                  const pcpp::IPv4Address& gateway,
                  const std::string& iface,
                  int metric = 1);

        void removeRoute(const pcpp::IPv4Address& network, const pcpp::IPv4Address& mask);

        std::optional<RouteEntry> findRoute(const pcpp::IPv4Address& destinationIP);

        void printTable() const;
};

#endif //BASIC_FIREWALL_ROUTING_TABLE_H
