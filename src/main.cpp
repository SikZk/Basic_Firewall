#include <iostream>
#include <vector>
#include <string>
#include <thread>
#include <chrono>
#include <csignal>
#include <unordered_set>
#include <memory>
#include "pcapplusplus/PcapLiveDeviceList.h"
#include "pcapplusplus/PcapLiveDevice.h"
#include "pcapplusplus/RawPacket.h"
#include "pcapplusplus/Packet.h"
#include "pcapplusplus/EthLayer.h"
#include "pcapplusplus/IPv4Layer.h"
#include "pcapplusplus/TcpLayer.h"
#include "pcapplusplus/IcmpLayer.h"

#include "../include/configuration/Config.h"

#include <netinet/in.h>

#include "../include/utils.h"
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

    RawPacket rawPacketCopy(*rawPacket);
    Packet packet(&rawPacketCopy);

    auto* eth = packet.getLayerOfType<EthLayer>();
    if (!eth) return;

    const pcpp::MacAddress destMac = eth->getDestMac();
    const pcpp::MacAddress myMac = inDev->getMacAddress();

    if (destMac != myMac && destMac != pcpp::MacAddress::Broadcast) {
        return;
    }
    if (eth->getSourceMac() == inDev->getMacAddress()) return;

    if (packet.isPacketOfType(ARP)) {
        routingEngine.processArpPacket(packet, inDev);
        return;
    }

    auto* ipLayer = packet.getLayerOfType<IPv4Layer>();
    if (!ipLayer) return;

    auto* tcpLayer = packet.getLayerOfType<TcpLayer>();
    DecryptionSession* decryptSession = nullptr;
    if (tcpLayer && isHttpsPacket(tcpLayer) && configuration.shouldDecryptTraffic(*ipLayer)) {
        const auto* tcpHeader = tcpLayer->getTcpHeader();
        SessionFlowKey decryptKey = getKeyFromPacket(packet);
        if (configuration.tls_mitm_enabled) {
            if (auto* existing = decryptionSessionTable.findSession(decryptKey)) {
                decryptSession = static_cast<DecryptionSession*>(existing);
            }
        } else {
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

            decryptSession = static_cast<DecryptionSession*>(existing);
            const uint8_t* payload = tcpLayer->getLayerPayload();
            const size_t payloadLen = tcpLayer->getLayerPayloadSize();
            if (payloadLen > 0) {
                decryptSession->processEncryptedData(payload, payloadLen);
                logDecryptedHttpIfReady(*decryptSession);
            }
        }
    }

    const SecurityPolicy* matched_policy = nullptr;
    for (const auto& policy : configuration.security_policies) {
        if (policy.does_match_policy(*ipLayer)) {
            matched_policy = &policy;
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

    if (matched_policy && !matched_policy->security_profiles.empty()) {
        for (const auto& profile : matched_policy->security_profiles) {
            if (!profile) {
                continue;
            }
            Action profileAction = ALLOW;
            if (decryptSession) {
                profileAction = profile->scan(*decryptSession, *ipLayer);
            } else {
                profileAction = profile->scan(nullptr, *ipLayer);
            }
            if (profileAction == BLOCK) {
                std::cout << "[SECURITY] Dropped packet by security profile: "
                          << ipLayer->getSrcIPv4Address().toString()
                          << " -> " << ipLayer->getDstIPv4Address().toString()
                          << std::endl;

                sendTcpRst(packet, inDev, routingEngine, natService, configuration.routing_table);
                return;
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

    if (ipLayer->getDstIPv4Address() == configuration.public_ip_addr) {
        if (debug) std::cout << "[DEBUG] Direction: INBOUND (Target is External IP)" << std::endl;
        if (Session* sessionPtr = state.table.findSession(key)) {
            NatSession* session = static_cast<NatSession*>(sessionPtr);
            natService.applyNat(*session, ipLayer);
            if (debug) std::cout << "[DEBUG] Applied Reverse NAT. New Dst: " << ipLayer->getDstIPv4Address().toString() << std::endl;
        }
    }
    else if (isInternalNetwork(ipLayer->getDstIPv4Address())) {
        if (debug) std::cout << "[DEBUG] Direction: INTERNAL ROUTING (Target is 10.x.x.x)" << std::endl;
    }
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
            NatSession* session = state.getOrCreateSession(key, configuration.public_ip_addr);
            if (session) {
                natService.applyNat(*session, ipLayer);
                if (debug) std::cout << "[DEBUG] Applied Source NAT. New Src: " << ipLayer->getSrcIPv4Address().toString() << std::endl;
            }
        } else {
            if (debug) std::cout << "[DEBUG] NO Policy Matched." << std::endl;
        }
    }

    routingEngine.routePacket(packet, inDev, configuration.routing_table);
}

int main()
{
    std::cout << "router start\n";

    std::cout << "[SYSTEM] Disabling Kernel Routing..." << std::endl;
    runCommand("sudo sysctl -w net.ipv4.ip_forward=0");

    std::cout << "[SYSTEM] Adding iptables rule to drop kernel handling of ports 10000-20000 on eth2..." << std::endl;
    runCommand("sudo iptables -A INPUT -i eth2 -p tcp --dport 10000:20000 -j DROP");

    std::signal(SIGINT, exitProgram);
    std::signal(SIGTERM, exitProgram);

    configuration.load();
    if (configuration.tls_mitm_enabled) {
        tlsMitmProxy = std::make_unique<TlsMitmProxy>(configuration);
        tlsMitmProxy->setDecryptedDataCallback(
            [](const pcpp::IPv4Address& src_ip,
               uint16_t src_port,
               const pcpp::IPv4Address& dst_ip,
               uint16_t dst_port,
               const std::string& data,
               bool from_client) {
                if (from_client) {
                    return;
                }
                SessionFlowKey key{
                    src_ip,
                    src_port,
                    dst_ip,
                    dst_port,
                    pcpp::TCP
                };
                auto* existing = decryptionSessionTable.findSession(key);
                if (!existing) {
                    DecryptionSession newSession(
                        src_ip,
                        src_ip,
                        src_port,
                        dst_ip,
                        dst_port
                    );
                    existing = &decryptionSessionTable.createSession(key, std::move(newSession));
                }
                auto* session = static_cast<DecryptionSession*>(existing);
                session->processDecryptedData(reinterpret_cast<const uint8_t*>(data.data()), data.size());
                logDecryptedHttpIfReady(*session);
            });
        tlsMitmProxy->start();
        configureTlsMitmRedirect(configuration.tls_mitm_port, true);
    }
    NatPolicy::configureNatState(10000, 20000);

    auto interfaces = configuration.getCaptureInterfaces();
    std::unordered_set<std::string> seen_interfaces;
    gInterfaces.clear();

    bool externalFound = false;
    for (auto* iface : interfaces) {
        if(iface->getName() == "eth2") externalFound = true;
    }
    if(!externalFound) {
        if(auto* dev = PcapLiveDeviceList::getInstance().getDeviceByName("eth2"))
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
