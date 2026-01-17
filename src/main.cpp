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


static void exitProgram(int)
{
    stopSignal = 1;
    for (auto* dev : gInterfaces)
    {
        if (dev && dev->isOpened())
            dev->stopCapture();
    }
}

static void onPacketArrives(RawPacket* rawPacket, PcapLiveDevice* inDev, void*)
{
    if (!rawPacket || !inDev)
        return;
    Packet packet(rawPacket);

    // Need Ethernet for L2 forwarding
    IPv4Layer* ipLayerPacket = packet.getLayerOfType<IPv4Layer>();



    auto* eth = packet.getLayerOfType<EthLayer>();
    if (!eth)
        return;

    const MacAddress dstMac = eth->getDestMac();
    if (dstMac != inDev->getMacAddress() && dstMac != MacAddress::Broadcast)
        return;
    // If we ever still see our injected frames, ignore
    if (eth->getSourceMac() == inDev->getMacAddress())
        return;

    const auto destMac = eth->getDestMac();
    if (destMac != inDev->getMacAddress() && destMac != pcpp::MacAddress::Broadcast)
        return;

    if (packet.isPacketOfType(ARP))
    {
        routingEngine.processArpPacket(packet, inDev);
        return;
    }


    if (!packet.isPacketOfType(IPv4))
        return;


    routingEngine.routePacket(packet, inDev);
}

int main()
{
    std::printf("router start\n");

    std::signal(SIGINT, exitProgram);
    std::signal(SIGTERM, exitProgram);

    configuration.load();

    // Load and DEDUP interfaces (avoid capturing the same interface multiple times)
    {
        auto ifs = configuration.getCaptureInterfaces();
        std::unordered_set<std::string> seen;
        gInterfaces.clear();
        gInterfaces.reserve(ifs.size());

        for (auto* dev : ifs)
        {
            if (!dev) continue;
            if (dev->getLoopback()) continue; // generally avoid "lo"

            const std::string name = dev->getName();
            if (seen.insert(name).second)
                gInterfaces.push_back(dev);
        }
    }

    routingEngine.loadInterfaces(gInterfaces);
    routingEngine.loadRoutingTable(configuration.routing_table);

    for (PcapLiveDevice* dev : gInterfaces)
    {
        // Open with explicit configuration: capture IN only (prevents out/loop duplicates)
        PcapLiveDevice::DeviceConfiguration cfg;
        cfg.mode = PcapLiveDevice::Promiscuous;
        cfg.direction = PcapLiveDevice::PCPP_IN;   // CRITICAL: inbound only :contentReference[oaicite:1]{index=1}
        cfg.snapshotLength = 65535;

        if (!dev->open(cfg))
        {
            std::cerr << "Failed to open: " << dev->getName() << std::endl;
            return 1;
        }

        // Optional: reduce work. You can keep your MAC filter if you want,
        // but it should no longer be necessary once direction=PCPP_IN.
        if (!dev->setFilter("arp or ip"))
        {
            std::cerr << "Failed to set filter on " << dev->getName() << std::endl;
        }

        if (!dev->startCapture(onPacketArrives, nullptr))
        {
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

    for (PcapLiveDevice* dev : gInterfaces)
    {
        if (dev && dev->isOpened())
            dev->close();
    }

    std::cout << "router stop\n";
    return 0;
}
