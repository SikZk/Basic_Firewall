//
// Created by mikolaj on 11/30/25.
//

#ifndef BASIC_FIREWALL_ROUTINGENGINE_H
#define BASIC_FIREWALL_ROUTINGENGINE_H
#include <pcapplusplus/IPv4Layer.h>
#include "pcapplusplus/MacAddress.h"
#include "pcapplusplus/PcapLiveDeviceList.h"
#include "RoutingTable.h"
#include <optional>
#include <unordered_map>

class RoutingEngine {
    private:
        static RoutingTable routing_table;
        std::vector<pcpp::PcapLiveDevice*> interfaces;
        std::unordered_map<uint32_t, pcpp::MacAddress> arpCache;
        std::optional<pcpp::MacAddress> resolveMacAddress(pcpp::PcapLiveDevice* device,
                                                          const pcpp::IPv4Address& nextHop);
    public:
        RoutingEngine();
        void routePacket(pcpp::IPv4Layer *ipLayerPacket, pcpp::IPv4Layer *originalIpLayerPacket);
        void loadInterfaces(std::vector<pcpp::PcapLiveDevice*> interfaces);
        void loadRoutingTable(const RoutingTable& table);
};

#endif //BASIC_FIREWALL_ROUTINGENGINE_H
