#ifndef BASIC_FIREWALL_ROUTING_TABLE_H
#define BASIC_FIREWALL_ROUTING_TABLE_H
#include <optional>
#include <string>
#include <vector>
#include <pcapplusplus/IpAddress.h>
/**
 * @brief Single routing table entry.
 */
struct RouteEntry {
    pcpp::IPv4Address network;
    pcpp::IPv4Address netmask;
    pcpp::IPv4Address gateway;
    std::string interfaceName;
};

/**
 * @brief Simple IPv4 routing table with longest-prefix match.
 */
class RoutingTable {
private:
    std::vector<RouteEntry> routes;

public:
    /**
     * @brief Construct an empty routing table.
     */
    RoutingTable() = default;

    /**
     * @brief Add a route entry.
     *
     * @param network Destination network.
     * @param mask Network mask.
     * @param gateway Next-hop gateway.
     * @param iface Interface name to use.
     * @param metric Route metric weight.
     */
    void addRoute(const pcpp::IPv4Address& network,
                  const pcpp::IPv4Address& mask,
                  const pcpp::IPv4Address& gateway,
                  const std::string& iface,
                  int metric = 1);

    /**
     * @brief Remove a route entry.
     *
     * @param network Destination network.
     * @param mask Network mask.
     */
    void removeRoute(const pcpp::IPv4Address& network, const pcpp::IPv4Address& mask);

    /**
     * @brief Find the best route for a destination.
     *
     * @param destinationIP Destination IPv4 address.
     * @return Matching route entry if found.
     */
    std::optional<RouteEntry> findRoute(const pcpp::IPv4Address& destinationIP);

    /**
     * @brief Print the routing table to stdout.
     */
    void printTable() const;
};

#endif
