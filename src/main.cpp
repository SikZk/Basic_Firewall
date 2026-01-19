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
#include "../include/session/session_tables/SessionTable.h"
#include "../include/session/session_tables/DecryptionSessionTable.h"

using namespace pcpp;

static volatile std::sig_atomic_t stopSignal = 0;

static Config configuration("../resources/config.json");
static RoutingEngine routingEngine;
static std::vector<PcapLiveDevice*> gInterfaces;
static NatService natService;
static SessionTable sessionTable;
static DecryptionSessionTable decryptionSessionTable;

const IPv4Address EXTERNAL_IP("192.168.1.39");

static void exitProgram(int) {
    stopSignal = 1;
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

const DecryptionProfile* findMatchingDecryptionProfile(
    const Session& session,
    const std::vector<DecryptionProfile>& profiles
)
{
    for (const auto& profile : profiles) {
        if (profile.doesMatchProfile(session)) {
            return &profile;
        }
    }
    return nullptr;
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

    TcpLayer* tcpLayer = packet.getLayerOfType<TcpLayer>();
    if (tcpLayer && tcpLayer->getLayerPayloadSize() > 0) {
        SessionFlowKey sessionKey = getSessionFlowKey(ipLayer, tcpLayer);
        Session* session = createOrGetSession(sessionTable, sessionKey, ipLayer, tcpLayer, inDev);
        const DecryptionProfile* profile = findMatchingDecryptionProfile(*session, configuration.decryption_profiles);

        uint16_t src_port = ntohs(tcpLayer->getTcpHeader()->portSrc);
        uint16_t dst_port = ntohs(tcpLayer->getTcpHeader()->portDst);
        bool is_https = (src_port == 443 || dst_port == 443);

        if (profile && profile->shouldDecrypt() && is_https) {
            if (!profile->ca_cert || !profile->ca_private_key) {
                std::cout << "[Decryption] Warning: profile '" << profile->profile_name
                          << "' missing CA material, logging without TLS replacement." << std::endl;
            }

            DecryptionSession* decrypt_session = createOrGetDecryptionSession(
                decryptionSessionTable,
                sessionKey,
                session,
                *profile
            );

            const uint8_t* payload = tcpLayer->getLayerPayload();
            size_t payload_length = tcpLayer->getLayerPayloadSize();
            decrypt_session->processEncryptedData(payload, payload_length);

            if (decrypt_session->hasCompleteHttpHeader()) {
                std::cout << "[Decryption] HTTP message (" << profile->profile_name << "):\n"
                          << decrypt_session->getDecryptedDataAsString() << std::endl;
                decrypt_session->clearBuffer();
            }
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
    if (finalIpLayer) {
        std::cout << "[FINAL SEND] Packet buffer check: "
                  << finalIpLayer->getSrcIPv4Address().toString()
                  << " -> "
                  << finalIpLayer->getDstIPv4Address().toString()
                  << std::endl;
    }
    routingEngine.routePacket(packet, inDev, configuration.routing_table);
}

int main()
{
    std::cout << "router start (DEEP COPY FIX)\n";
    std::signal(SIGINT, exitProgram);
    std::signal(SIGTERM, exitProgram);

    configuration.load();
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
