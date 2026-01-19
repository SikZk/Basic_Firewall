// --- 1. Include ALL System & Library Headers FIRST ---
#include <iostream>
#include <vector>
#include <string>
#include <sstream>
#include <thread>
#include <chrono>
#include <csignal>
#include <cstdio>
#include <unordered_set>
#include <mutex>
#include <optional>
#include <algorithm>
#include <cstring>
#include <memory>
#include <cstdlib>

// Include Boost headers
#include <boost/json.hpp>
#include <boost/unordered_set.hpp>
#include <boost/unordered_map.hpp>

// Include PcapPlusPlus headers
#include "pcapplusplus/PcapLiveDeviceList.h"
#include "pcapplusplus/PcapLiveDevice.h"
#include "pcapplusplus/RawPacket.h"
#include "pcapplusplus/Packet.h"
#include "pcapplusplus/EthLayer.h"
#include "pcapplusplus/IPv4Layer.h"
#include "pcapplusplus/TcpLayer.h"
#include "pcapplusplus/IcmpLayer.h"
#include "pcapplusplus/ArpLayer.h"

// --- 2. Apply the Access Hack ---
#define private public
#include "../include/configuration/Config.h"
#undef private
// --- 3. End Access Hack ---

#include <netinet/in.h>

#include "utils.h"
#include "../include/routing/RoutingEngine.h"
#include "../include/policies/NatService.h"
#include "../include/session/session_tables/DecryptionSessionTable.h"
#include "../include/decryption/TlsMitmProxy.h"

using namespace pcpp;

static volatile std::sig_atomic_t stopSignal = 0;

static Config configuration("../resources/config.json");
static RoutingEngine routingEngine;
static std::vector<PcapLiveDevice*> gInterfaces;
static NatService natService;
static DecryptionSessionTable decryptionSessionTable;
static std::unique_ptr<TlsMitmProxy> tlsMitmProxy;

const IPv4Address EXTERNAL_IP("192.168.1.39");

bool runCommand(const std::string& command)
{
    int result = std::system(command.c_str());
    return result == 0;
}

void configureTlsMitmRedirect(uint16_t port, bool enable)
{
    std::string action = enable ? "-A" : "-D";
    std::string base = "iptables -t nat " + action +
                       " PREROUTING -p tcp --dport 443 -j REDIRECT --to-ports " +
                       std::to_string(port);
    if (!runCommand(base)) {
        std::cerr << "[TLS MITM] Failed to update iptables redirect rule: " << base << std::endl;
    }
}

static void exitProgram(int) {
    stopSignal = 1;
    if (tlsMitmProxy) {
        tlsMitmProxy->stop();
    }
    if (configuration.tls_mitm_enabled) {
        configureTlsMitmRedirect(configuration.tls_mitm_port, false);
    }
    for (auto* dev : gInterfaces) {
        if (dev && dev->isOpened())
            dev->stopCapture();
    }
}

SessionFlowKey getKeyFromPacket(Packet& packet) {
    IPv4Layer* ip = packet.getLayerOfType<IPv4Layer>();
    TcpLayer* tcp = packet.getLayerOfType<TcpLayer>();
    IcmpLayer* icmp = packet.getLayerOfType<IcmpLayer>();

    SessionFlowKey key;
    if (!ip) return key;

    key.src_ip = ip->getSrcIPv4Address();
    key.dst_ip = ip->getDstIPv4Address();

    if (tcp) {
        key.protocol = pcpp::TCP;
        key.src_port = ntohs(tcp->getTcpHeader()->portSrc);
        key.dst_port = ntohs(tcp->getTcpHeader()->portDst);
    } else if (icmp) {
        key.protocol = pcpp::ICMP;
        uint16_t id = 0;
        if (icmp->getData() && icmp->getDataLen() >= 6) {
            id = ntohs(*reinterpret_cast<uint16_t*>(icmp->getData() + 4));
        }
        key.src_port = id;
        key.dst_port = id;
    } else {
        key.protocol = pcpp::PacketTrailer;
    }
    return key;
}

bool isInternalNetwork(const IPv4Address& ip) {
    return ip.toString().rfind("10.", 0) == 0;
}

bool isHttpsPacket(const TcpLayer* tcpLayer)
{
    if (!tcpLayer) {
        return false;
    }
    const auto* header = tcpLayer->getTcpHeader();
    if (!header) {
        return false;
    }
    uint16_t src_port = ntohs(header->portSrc);
    uint16_t dst_port = ntohs(header->portDst);
    return src_port == 443 || dst_port == 443;
}

bool shouldDecryptTraffic(const IPv4Layer& ipLayer)
{
    for (const auto& profile : configuration.decryption_profiles) {
        if (!profile.shouldDecrypt()) {
            continue;
        }
        if (profile.matchesEndpoints(ipLayer.getSrcIPv4Address(), ipLayer.getDstIPv4Address())) {
            return true;
        }
    }
    return false;
}

void logDecryptedHttpIfReady(DecryptionSession& session)
{
    if (!session.hasCompleteHttpHeader()) {
        return;
    }
    const auto data = session.getDecryptedDataAsString();
    std::cout << "[HTTPS Decrypt] HTTP payload:" << std::endl;
    std::cout << data << std::endl;
    session.clearBuffer();
}

static void onPacketArrives(RawPacket* rawPacket, PcapLiveDevice* inDev, void*)
{
    if (!rawPacket || !inDev) return;

    // --- KLUCZOWA ZMIANA ---
    // Tworzymy kopię surowego pakietu.
    // Dzięki temu mamy własny bufor pamięci, który możemy bezpiecznie modyfikować (NAT)
    // i który RoutingEngine wyśle dalej.
    RawPacket rawPacketCopy(*rawPacket);
    Packet packet(&rawPacketCopy);
    // -----------------------

    EthLayer* eth = packet.getLayerOfType<EthLayer>();
    if (!eth) return;

    pcpp::MacAddress destMac = eth->getDestMac();
    pcpp::MacAddress myMac = inDev->getMacAddress();

    // Jeśli to NIE jest do nas I NIE jest to Broadcast -> Drop
    if (destMac != myMac && destMac != pcpp::MacAddress::Broadcast) {
        // Opcjonalnie: Debug log, żebyś widział co odrzucasz
        // std::cout << "[DROP] Ignoring noise packet not for me. Dst: " << destMac.toString() << std::endl;
        return;
    }
    if (eth->getSourceMac() == inDev->getMacAddress()) return;

    if (packet.isPacketOfType(ARP)){
        routingEngine.processArpPacket(packet, inDev);
        return;
    }

    IPv4Layer* ipLayer = packet.getLayerOfType<IPv4Layer>();
    if (!ipLayer) return;

    TcpLayer* tcpLayer = packet.getLayerOfType<TcpLayer>();
    if (tcpLayer && isHttpsPacket(tcpLayer) && shouldDecryptTraffic(*ipLayer)) {
        const auto* tcpHeader = tcpLayer->getTcpHeader();
        SessionFlowKey decryptKey = getKeyFromPacket(packet);
        auto* existing = decryptionSessionTable.findSession(decryptKey);
        if (!existing) {
            DecryptionSession newSession(
                inDev->getIPv4Address(),
                ipLayer->getSrcIPv4Address(),
                ntohs(tcpHeader->portSrc),
                ipLayer->getDstIPv4Address(),
                ntohs(tcpHeader->portDst)
            );
            existing = &decryptionSessionTable.createSession(decryptKey, std::move(newSession));
        }

        auto* decryptSession = static_cast<DecryptionSession*>(existing);
        const uint8_t* payload = tcpLayer->getLayerPayload();
        size_t payloadLen = tcpLayer->getLayerPayloadSize();
        if (payloadLen > 0) {
            decryptSession->processEncryptedData(payload, payloadLen);
            logDecryptedHttpIfReady(*decryptSession);
        }
    }

    for (const auto& policy : configuration.security_policies) {
        if (policy.does_match_policy(*ipLayer)) {
            if (!policy.allowsPacket()) {
                std::cout << "[SECURITY] Dropped packet: "
                          << ipLayer->getSrcIPv4Address().toString()
                          << " -> " << ipLayer->getDstIPv4Address().toString()
                          << std::endl;
                return;
            }
            break;
        }
    }

    SessionFlowKey key = getKeyFromPacket(packet);

    bool debug = (key.protocol == pcpp::ICMP);
    if (debug) {
        std::cout << "[DEBUG] Packet: " << ipLayer->getSrcIPv4Address().toString()
                  << " -> " << ipLayer->getDstIPv4Address().toString()
                  << " [Protocol: " << (int)key.protocol << "]" << std::endl;
    }

    NatState& state = NatPolicy::nat_state;

    // 1. Inbound (Return Traffic)
    if (ipLayer->getDstIPv4Address() == EXTERNAL_IP) {
        if (debug) std::cout << "[DEBUG] Direction: INBOUND (Target is External IP)" << std::endl;
        if (Session* sessionPtr = state.table.findSession(key)) {
            NatSession* session = static_cast<NatSession*>(sessionPtr);
            natService.applyNat(*session, ipLayer);
            if (debug) std::cout << "[DEBUG] Applied Reverse NAT. New Dst: " << ipLayer->getDstIPv4Address().toString() << std::endl;
        }
    }
    // 2. Internal Routing
    else if (isInternalNetwork(ipLayer->getDstIPv4Address())) {
        if (debug) std::cout << "[DEBUG] Direction: INTERNAL ROUTING (Target is 10.x.x.x)" << std::endl;
    }
    // 3. Outbound (Internet)
    else if (!configuration.nat_policies.empty()) {
        if (debug) std::cout << "[DEBUG] Direction: OUTBOUND (Checking Policies...)" << std::endl;

        bool matchesPolicy = false;
        for(auto& pol : configuration.nat_policies) {
            if(pol.does_match_policy(*ipLayer)) {
                matchesPolicy = true;
                break;
            }
        }

        if (matchesPolicy) {
            if (debug) std::cout << "[DEBUG] Policy MATCHED. Getting Session..." << std::endl;
            NatSession* session = state.getOrCreateSession(key, EXTERNAL_IP);
            if (session) {
                natService.applyNat(*session, ipLayer);
                if (debug) std::cout << "[DEBUG] Applied Source NAT. New Src: " << ipLayer->getSrcIPv4Address().toString() << std::endl;
            }
        } else {
            if (debug) std::cout << "[DEBUG] NO Policy Matched." << std::endl;
        }
    }

    // Wyślij zmodyfikowaną kopię pakietu
    pcpp::IPv4Layer* finalIpLayer = packet.getLayerOfType<pcpp::IPv4Layer>();
    // if (finalIpLayer) {
    //     std::cout << "[FINAL SEND] Packet buffer check: "
    //               << finalIpLayer->getSrcIPv4Address().toString()
    //               << " -> "
    //               << finalIpLayer->getDstIPv4Address().toString()
    //               << std::endl;
    // }
    routingEngine.routePacket(packet, inDev, configuration.routing_table);
}

int main()
{
    std::cout << "router start (DEEP COPY FIX)\n";
    std::signal(SIGINT, exitProgram);
    std::signal(SIGTERM, exitProgram);

    configuration.load();
    if (configuration.tls_mitm_enabled) {
        tlsMitmProxy = std::make_unique<TlsMitmProxy>(configuration);
        tlsMitmProxy->start();
        configureTlsMitmRedirect(configuration.tls_mitm_port, true);
    }
    NatPolicy::configureNatState(10000, 20000);

    auto interfaces = configuration.getCaptureInterfaces();
    std::unordered_set<std::string> seen_interfaces;
    gInterfaces.clear();

    bool externalFound = false;
    for (auto* iface : interfaces) {
        if(iface->getName() == "ens34") externalFound = true;
    }
    if(!externalFound) {
        if(auto* dev = PcapLiveDeviceList::getInstance().getDeviceByName("ens34"))
            interfaces.push_back(dev);
    }

    for (PcapLiveDevice* interface : interfaces) {
        if (!interface || interface->getLoopback()) continue;
        if (seen_interfaces.insert(interface->getName()).second)
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
        if (!dev->setFilter("arp or ip or icmp")) {
            std::cerr << "Failed to set filter on " << dev->getName() << std::endl;
        }
        if (!dev->startCapture(onPacketArrives, nullptr)) {
            std::cerr << "Failed to start capture: " << dev->getName() << std::endl;
            dev->close();
            return 1;
        }
        std::cout << "Capturing on: " << dev->getName() << std::endl;
    }

    while (!stopSignal)
        std::this_thread::sleep_for(std::chrono::milliseconds(200));

    for (PcapLiveDevice* dev : gInterfaces) {
        if (dev && dev->isOpened()) dev->close();
    }

    std::cout << "router stop\n";
    return 0;
}
