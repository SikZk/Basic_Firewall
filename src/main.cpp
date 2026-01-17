// main.cpp
#include "pcapplusplus/PcapLiveDeviceList.h"
#include "pcapplusplus/PcapLiveDevice.h"
#include "pcapplusplus/RawPacket.h"
#include "pcapplusplus/Packet.h"
#include "pcapplusplus/EthLayer.h"
#include "pcapplusplus/IPv4Layer.h"
#include "pcapplusplus/ArpLayer.h"

#include <cstdio>
#include <csignal>
#include <thread>
#include <chrono>
#include <iostream>
#include <vector>
#include <string>
#include <unordered_set>

#include "utils.h"
#include "../include/configuration/Config.h"
#include "../include/routing/RoutingEngine.h"


using namespace pcpp;

static volatile std::sig_atomic_t stopSignal = 0;

static Config configuration("../resources/config.json");
static RoutingEngine routingEngine;
static std::vector<PcapLiveDevice*> gInterfaces;


static void exitProgram(int) {
    stopSignal = 1;
    for (auto* dev : gInterfaces) {
        if (dev && dev->isOpened())
            dev->stopCapture();
    }
}

static void onPacketArrives(RawPacket* rawPacket, PcapLiveDevice* inDev, void*)
{
    if (!rawPacket || !inDev)
        return;

    Packet packet(rawPacket);
    EthLayer* eth = packet.getLayerOfType<EthLayer>();

    if (!eth) return;

    const MacAddress dstMac = eth->getDestMac();
    if (dstMac != inDev->getMacAddress() && dstMac != MacAddress::Broadcast)
        return;
    if (eth->getSourceMac() == inDev->getMacAddress())
        return;
    if (dstMac != inDev->getMacAddress() && dstMac != pcpp::MacAddress::Broadcast)
        return;
    if (packet.isPacketOfType(ARP)){
        routingEngine.processArpPacket(packet, inDev);
        return;
    }
    if (!packet.isPacketOfType(IPv4))
        return;

    routingEngine.routePacket(packet, inDev, configuration.routing_table, configuration.nat_policies);
}

int main()
{
    std::cout << "router start\n";
    std::signal(SIGINT, exitProgram);
    std::signal(SIGTERM, exitProgram);

    configuration.load();

    auto interfaces  = configuration.getCaptureInterfaces();
    std::unordered_set<std::string> seen_interfaces;
    gInterfaces.clear();
    gInterfaces.reserve(interfaces.size());

    for (PcapLiveDevice* interface : interfaces) {
        if (!interface) continue;
        if (interface->getLoopback()) continue;

        const std::string name = interface->getName();
        if (seen_interfaces.insert(name).second)
            gInterfaces.push_back(interface);
    }

    routingEngine.loadInterfaces(gInterfaces);

    for (PcapLiveDevice* dev : gInterfaces) {
        PcapLiveDevice::DeviceConfiguration cfg;
        cfg.mode = PcapLiveDevice::Promiscuous;
        cfg.direction = PcapLiveDevice::PCPP_IN;
        cfg.snapshotLength = 65535;

        if (!dev->open(cfg)) {
            std::cerr << "Failed to open: " << dev->getName() << std::endl;
            return 1;
        }
        if (!dev->setFilter("arp or ip")) {
            std::cerr << "Failed to set filter on " << dev->getName() << std::endl;
        }
        if (!dev->startCapture(onPacketArrives, nullptr)) {
            std::cerr << "Failed to start capture: " << dev->getName() << std::endl;
            dev->close();
            return 1;
        }

        std::cout << "Capturing IN on: " << dev->getName()
                  << " IP=" << dev->getIPv4Address().toString()
                  << " MAC=" << dev->getMacAddress().toString()
                  << std::endl;
    }

    while (!stopSignal)
        std::this_thread::sleep_for(std::chrono::milliseconds(200));

    for (PcapLiveDevice* dev : gInterfaces) {
        if (dev && dev->isOpened())
            dev->close();
    }

    std::cout << "router stop\n";
    return 0;
}
