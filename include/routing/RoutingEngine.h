//
// Created by mikolaj on 11/30/25.
//

#ifndef BASIC_FIREWALL_ROUTINGENGINE_H
#define BASIC_FIREWALL_ROUTINGENGINE_H
#include <pcapplusplus/IPv4Layer.h>
#include <pcapplusplus/Packet.h>
#include "pcapplusplus/PcapLiveDeviceList.h"
#include "RoutingTable.h"

class RoutingEngine {
    private:
        static RoutingTable routing_table;
        std::vector<pcpp::PcapLiveDevice*> interfaces;
    public:
        RoutingEngine();
        void routePacket(pcpp::Packet& packet, pcpp::IPv4Layer *ipLayerPacket);
        void loadInterfaces(std::vector<pcpp::PcapLiveDevice*> interfaces);
        void loadRoutingTable(const RoutingTable& table);
};

#endif //BASIC_FIREWALL_ROUTINGENGINE_H
