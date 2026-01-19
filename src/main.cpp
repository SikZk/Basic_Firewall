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

std::optional<std::string> extractSniFromTlsClientHello(const uint8_t* data, size_t length)
{
    if (!data || length < 5) {
        return std::nullopt;
    }
    if (data[0] != 0x16) {
        return std::nullopt;
    }
    uint16_t record_length = (static_cast<uint16_t>(data[3]) << 8) | data[4];
    if (record_length + 5 > length) {
        return std::nullopt;
    }
    size_t pos = 5;
    if (pos + 4 > length || data[pos] != 0x01) {
        return std::nullopt;
    }
    uint32_t handshake_length =
        (static_cast<uint32_t>(data[pos + 1]) << 16) |
        (static_cast<uint32_t>(data[pos + 2]) << 8) |
        data[pos + 3];
    pos += 4;
    if (pos + handshake_length > length) {
        return std::nullopt;
    }
    if (pos + 2 + 32 > length) {
        return std::nullopt;
    }
    pos += 2 + 32;
    if (pos + 1 > length) {
        return std::nullopt;
    }
    uint8_t session_id_len = data[pos];
    pos += 1 + session_id_len;
    if (pos + 2 > length) {
        return std::nullopt;
    }
    uint16_t cipher_suites_len = (static_cast<uint16_t>(data[pos]) << 8) | data[pos + 1];
    pos += 2 + cipher_suites_len;
    if (pos + 1 > length) {
        return std::nullopt;
    }
    uint8_t compression_len = data[pos];
    pos += 1 + compression_len;
    if (pos + 2 > length) {
        return std::nullopt;
    }
    uint16_t extensions_len = (static_cast<uint16_t>(data[pos]) << 8) | data[pos + 1];
    pos += 2;
    if (pos + extensions_len > length) {
        return std::nullopt;
    }
    size_t extensions_end = pos + extensions_len;
    while (pos + 4 <= extensions_end) {
        uint16_t ext_type = (static_cast<uint16_t>(data[pos]) << 8) | data[pos + 1];
        uint16_t ext_len = (static_cast<uint16_t>(data[pos + 2]) << 8) | data[pos + 3];
        pos += 4;
        if (pos + ext_len > extensions_end) {
            return std::nullopt;
        }
        if (ext_type == 0x0000 && ext_len >= 5) {
            size_t server_name_list_len = (static_cast<uint16_t>(data[pos]) << 8) | data[pos + 1];
            size_t list_pos = pos + 2;
            size_t list_end = list_pos + server_name_list_len;
            if (list_end > pos + ext_len) {
                return std::nullopt;
            }
            while (list_pos + 3 <= list_end) {
                uint8_t name_type = data[list_pos];
                uint16_t name_len = (static_cast<uint16_t>(data[list_pos + 1]) << 8) | data[list_pos + 2];
                list_pos += 3;
                if (list_pos + name_len > list_end) {
                    return std::nullopt;
                }
                if (name_type == 0x00 && name_len > 0) {
                    return std::string(reinterpret_cast<const char*>(data + list_pos), name_len);
                }
                list_pos += name_len;
            }
        }
        pos += ext_len;
    }
    return std::nullopt;
}

bool extractHttpHostAndPath(const uint8_t* data, size_t length, std::string& host, std::string& path)
{
    if (!data || length == 0) {
        return false;
    }
    constexpr size_t kMaxInspect = 4096;
    size_t inspect_len = std::min(length, kMaxInspect);
    std::string payload(reinterpret_cast<const char*>(data), inspect_len);
    auto line_end = payload.find("\r\n");
    if (line_end == std::string::npos) {
        return false;
    }
    std::string request_line = payload.substr(0, line_end);
    auto first_space = request_line.find(' ');
    auto second_space = request_line.find(' ', first_space == std::string::npos ? 0 : first_space + 1);
    if (first_space != std::string::npos && second_space != std::string::npos) {
        path = request_line.substr(first_space + 1, second_space - first_space - 1);
    }

    std::string lower_payload = payload;
    std::transform(lower_payload.begin(), lower_payload.end(), lower_payload.begin(), [](unsigned char ch) {
        return static_cast<char>(std::tolower(ch));
    });
    std::string host_marker = "\r\nhost:";
    auto host_pos = lower_payload.find(host_marker);
    if (host_pos == std::string::npos && lower_payload.rfind("host:", 0) == 0) {
        host_pos = 0;
    }
    if (host_pos != std::string::npos) {
        size_t value_start = host_pos == 0 ? 5 : host_pos + host_marker.size();
        while (value_start < payload.size() && (payload[value_start] == ' ' || payload[value_start] == '\t')) {
            ++value_start;
        }
        auto value_end = payload.find("\r\n", value_start);
        if (value_end != std::string::npos && value_end > value_start) {
            host = payload.substr(value_start, value_end - value_start);
        }
    }

    if (host.empty() && !path.empty()) {
        std::string lower_path = path;
        std::transform(lower_path.begin(), lower_path.end(), lower_path.begin(), [](unsigned char ch) {
            return static_cast<char>(std::tolower(ch));
        });
        std::string scheme = "http://";
        if (lower_path.rfind(scheme, 0) == 0) {
            auto host_start = scheme.size();
            auto slash = lower_path.find('/', host_start);
            host = path.substr(host_start, slash == std::string::npos ? std::string::npos : slash - host_start);
            path = slash == std::string::npos ? "/" : path.substr(slash);
        } else {
            scheme = "https://";
            if (lower_path.rfind(scheme, 0) == 0) {
                auto host_start = scheme.size();
                auto slash = lower_path.find('/', host_start);
                host = path.substr(host_start, slash == std::string::npos ? std::string::npos : slash - host_start);
                path = slash == std::string::npos ? "/" : path.substr(slash);
            }
        }
    }

    return !host.empty();
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

    if (!configuration.url_filtering_policies.empty() && tcpLayer) {
        const uint8_t* payload = tcpLayer->getLayerPayload();
        size_t payloadLen = tcpLayer->getLayerPayloadSize();
        std::string httpHost;
        std::string httpPath;
        bool hasHttpIndicator = extractHttpHostAndPath(payload, payloadLen, httpHost, httpPath);
        std::optional<std::string> sniHost;
        if (isHttpsPacket(tcpLayer)) {
            sniHost = extractSniFromTlsClientHello(payload, payloadLen);
        }

        if (hasHttpIndicator || (sniHost && !sniHost->empty())) {
            for (const auto& policy : configuration.url_filtering_policies) {
                if (!policy.does_match_policy(*ipLayer)) {
                    continue;
                }
                bool blocked = false;
                if (hasHttpIndicator) {
                    blocked = policy.isBlockedUrl(httpHost, httpPath);
                }
                if (!blocked && sniHost) {
                    blocked = policy.isBlockedHost(*sniHost);
                }
                if (blocked) {
                    std::cout << "[URL FILTER] Dropped packet: "
                              << ipLayer->getSrcIPv4Address().toString()
                              << " -> " << ipLayer->getDstIPv4Address().toString();
                    if (!httpHost.empty()) {
                        std::cout << " host=" << httpHost;
                    } else if (sniHost) {
                        std::cout << " sni=" << *sniHost;
                    }
                    if (!httpPath.empty()) {
                        std::cout << " path=" << httpPath;
                    }
                    std::cout << std::endl;
                    return;
                }
            }
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
