// main.cpp
#include "pcapplusplus/PcapLiveDeviceList.h"
#include "pcapplusplus/PcapLiveDevice.h"
#include "pcapplusplus/RawPacket.h"
#include "pcapplusplus/Packet.h"
#include "pcapplusplus/IPv4Layer.h"

#include <cstdio>
#include <cctype>
#include <csignal>
#include <iostream>
#include <thread>
#include <chrono>

using namespace pcpp;

static PcapLiveDevice* captureInterface = nullptr;
static volatile std::sig_atomic_t stopSignal = 0;

static void exitProgram(int) {
    stopSignal = 1;
    if (captureInterface && captureInterface->isOpened()) {
        captureInterface->stopCapture();
    }
}

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
        hexDump(ipLayer->getData(), ipLayer->getDataLen());
    }
}

int main() {
    std::signal(SIGINT, exitProgram);
    std::signal(SIGSTOP, exitProgram);

    captureInterface = PcapLiveDeviceList::getInstance().getDeviceByName("wlp0s20f3");
    if (!captureInterface->open()) {
        return 1;
    }
    if (!captureInterface->open()) {
        return 1;
    }

    if (!captureInterface->startCapture(onPacketArrives, nullptr)) {
        captureInterface->close();
        return 1;
    }

    while (!stopSignal) {
        std::this_thread::sleep_for(std::chrono::milliseconds(200));
    }

    captureInterface->close();
    std::printf("Capture stopped.\n");
    return 0;
}
