// main.cpp
#include "pcapplusplus/PcapLiveDeviceList.h"
#include "pcapplusplus/PcapLiveDevice.h"
#include "pcapplusplus/RawPacket.h"
#include "pcapplusplus/Packet.h"
#include "pcapplusplus/IPv4Layer.h"

#include <cstdio>
#include <cstdint>
#include <cctype>
#include <csignal>
#include <iostream>
#include <thread>
#include <chrono>

using namespace pcpp;

static PcapLiveDevice* gDev = nullptr;
static volatile std::sig_atomic_t gStop = 0;

static void hexDump(const uint8_t* data, size_t len) {
    for (size_t i = 0; i < len; i += 16) {
        std::printf("%08zx  ", i);
        for (size_t j = 0; j < 16; ++j) {
            if (i + j < len) std::printf("%02x ", data[i + j]);
            else std::printf("   ");
            if (j == 7) std::printf(" ");
        }
        std::printf(" |");
        for (size_t j = 0; j < 16 && i + j < len; ++j) {
            unsigned char c = data[i + j];
            std::printf("%c", std::isprint(c) ? c : '.');
        }
        std::printf("|\n");
    }
    std::printf("\n");
    std::fflush(stdout);
}

static void onPacketArrives(RawPacket* rawPacket, PcapLiveDevice* /*dev*/, void* /*user*/) {
    Packet parsedPacket(rawPacket);
    hexDump(rawPacket->getRawData(), rawPacket->getRawDataLen());

    if (parsedPacket.isPacketOfType(pcpp::IPv4)) {
        auto* ipLayer = parsedPacket.getLayerOfType<pcpp::IPv4Layer>();
        if (ipLayer) {
            std::cout << "Source IP: " << ipLayer->getSrcIPv4Address().toString()
                      << " --> Destination IP: " << ipLayer->getDstIPv4Address().toString()
                      << std::endl;
        }
    }

}

static void onSigInt(int) {
    gStop = 1;
    if (gDev && gDev->isOpened()) gDev->stopCapture();
}

int main() {
    std::signal(SIGINT, onSigInt);

    gDev = PcapLiveDeviceList::getInstance().getPcapLiveDeviceByName("wlp0s20f3");
    if (!gDev) {
        std::fprintf(stderr, "Interface 'wlp0s20f3' not found.\n");
        return 1;
    }

    if (!gDev->open()) {
        std::fprintf(stderr, "Failed to open interface.\n");
        return 1;
    }

    if (!gDev->startCapture(onPacketArrives, nullptr)) {
        std::fprintf(stderr, "Failed to start capture.\n");
        gDev->close();
        return 1;
    }

    while (!gStop) {
        std::this_thread::sleep_for(std::chrono::milliseconds(200));
    }

    gDev->close();
    std::printf("Capture stopped.\n");
    return 0;
}
