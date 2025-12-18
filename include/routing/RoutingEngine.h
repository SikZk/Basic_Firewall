//
// Created by mikolaj on 11/30/25.
//

#ifndef BASIC_FIREWALL_ROUTINGENGINE_H
#define BASIC_FIREWALL_ROUTINGENGINE_H
#include <pcapplusplus/IPv4Layer.h>
#include <vector>
#include <pcapplusplus/PcapLiveDevice.h>

#include "RoutingTable.h"

class RoutingEngine {
    private:
        static RoutingTable routing_table;
        std::vector<pcpp::PcapLiveDevice*> interfaces;
    public:
        RoutingEngine();
        void routePacket(pcpp::IPv4Layer *ipLayerPacket, pcpp::IPv4Layer *originalIpLayerPacket);
        void loadInterfaces(std::vector<pcpp::PcapLiveDevice*> interfaces);
};

#endif //BASIC_FIREWALL_ROUTINGENGINE_H
