#include <algorithm>
#include <fstream>
#include <sstream>
#include <stdexcept>
#include <regex>
#include <iomanip>
#include <iostream>
#include <arpa/inet.h>
#include <boost/unordered_map.hpp>
#include <vector>
#include <utility>
#include <boost/json.hpp>
#include <openssl/pem.h>
#include <openssl/ssl.h>
#include <pcapplusplus/TcpLayer.h>
#include <pcapplusplus/IpAddress.h>
#include <pcapplusplus/Packet.h>
#include "../include/configuration/Config.h"
#include "../include/policies/SecurityPolicy.h"
#include "../include/policies/NatPolicy.h"
#include "../include/policies/NatService.h"
#include "../include/security_profiles/DlpProfile.h"
#include "../include/security_profiles/AntimalwareProfile.h"
#include "../include/security_profiles/UrlFilteringProfile.h"
#include "../include/session/sessions/DecryptionSession.h"
#include "../include/decryption/DecryptionManager.h"
#include "../include/routing/RoutingEngine.h"
#include "./utils.h"

using namespace pcpp;

// ------------------------- Config -------------------------

void Config::load() {
    loadFromFile(configuration_file_path);
}

void Config::loadFromFile(const std::string& filepath) {
    std::ifstream file_stream(filepath);
    if (!file_stream) {
        throw std::runtime_error("Cannot open configuration file: " + filepath);
    }
    std::stringstream buffer;
    buffer << file_stream.rdbuf();
    auto json_value = boost::json::parse(buffer.str());

    if (!json_value.is_object()) {
        throw std::runtime_error("Configuration file is not a JSON object");
    }
    const auto& obj = json_value.as_object();
    if (auto it = obj.find("decryption_profiles"); it != obj.end()) {
        parseDecryptionProfile(it->value());
    }
    if (auto it = obj.find("security_policies"); it != obj.end()) {
        parseSecurityPolicy(it->value());
    }
    if (auto it = obj.find("nat_policies"); it != obj.end()) {
        parseNatPolicy(it->value());
    }
    if (auto it = obj.find("routing"); it != obj.end()) {
        parseRoutingTable(it->value());
    }
    if (auto it = obj.find("interfaces"); it != obj.end()) {
        parseInterfaces(it->value());
    }
    if (auto it = obj.find("malware_db"); it != obj.end()) {
        loadMalwareDatabase(it->value());
    }
}

void Config::parseInterfaces(const boost::json::value& object) {
    if (!object.is_object()) return;
    const auto& iface_obj = object.as_object();
    for (const auto& [_, iface_name] : iface_obj) {
        if (!iface_name.is_string()) continue;
        auto device = PcapLiveDeviceList::getInstance().getPcapLiveDeviceByName(iface_name.as_string().c_str());
        if (device != nullptr) {
            capture_interfaces.push_back(device);
        }
    }
}

void Config::parseDecryptionProfile(const boost::json::value& object) {
    if (!object.is_array()) return;
    for (const auto& elem : object.as_array()) {
        if (!elem.is_object()) continue;
        const auto& obj = elem.as_object();
        auto name   = obj.if_contains("name")  ? obj.at("name").as_string().c_str()  : "";
        auto ca     = obj.if_contains("ca")    ? obj.at("ca").as_string().c_str()    : "";
        auto key    = obj.if_contains("key")   ? obj.at("key").as_string().c_str()   : "";
        auto from   = obj.if_contains("from")  ? obj.at("from").as_string().c_str()  : "0.0.0.0";
        auto to     = obj.if_contains("to")    ? obj.at("to").as_string().c_str()    : "0.0.0.0";
        auto from_m = obj.if_contains("from_mask") ? obj.at("from_mask").as_int64()  : 0;
        auto to_m   = obj.if_contains("to_mask")   ? obj.at("to_mask").as_int64()    : 0;
        decryption_profiles.emplace_back(
            std::string(name),
            std::string(ca),
            std::string(key),
            std::string(from),
            static_cast<uint32_t>(from_m),
            std::string(to),
            static_cast<uint32_t>(to_m)
        );
    }
}

void Config::parseSecurityPolicy(const boost::json::value& object) {
    if (!object.is_array()) return;
    for (const auto& elem : object.as_array()) {
        if (!elem.is_object()) continue;
        const auto& obj = elem.as_object();
        auto from   = obj.if_contains("from")  ? obj.at("from").as_string().c_str()  : "0.0.0.0";
        auto to     = obj.if_contains("to")    ? obj.at("to").as_string().c_str()    : "0.0.0.0";
        auto from_m = obj.if_contains("from_mask") ? obj.at("from_mask").as_int64()  : 0;
        auto to_m   = obj.if_contains("to_mask")   ? obj.at("to_mask").as_int64()    : 0;
        auto src_p  = obj.if_contains("src_port")  ? obj.at("src_port").as_int64()   : 0;
        auto dst_p  = obj.if_contains("dst_port")  ? obj.at("dst_port").as_int64()   : 0;
        auto allow  = obj.if_contains("allow")     ? obj.at("allow").as_bool()       : true;
        security_policies.emplace_back(
            std::string(from),
            static_cast<uint32_t>(from_m),
            std::string(to),
            static_cast<uint32_t>(to_m),
            static_cast<std::uint16_t>(src_p),
            static_cast<std::uint16_t>(dst_p),
            allow,
            std::vector<std::shared_ptr<SecurityProfile>>{}
        );
    }
}

void Config::parseNatPolicy(const boost::json::value& object) {
    if (!object.is_array()) return;
    for (const auto& elem : object.as_array()) {
        if (!elem.is_object()) continue;
        const auto& obj = elem.as_object();
        auto from   = obj.if_contains("from")  ? obj.at("from").as_string().c_str()  : "0.0.0.0";
        auto to     = obj.if_contains("to")    ? obj.at("to").as_string().c_str()    : "0.0.0.0";
        auto from_m = obj.if_contains("from_mask") ? obj.at("from_mask").as_int64()  : 0;
        auto to_m   = obj.if_contains("to_mask")   ? obj.at("to_mask").as_int64()    : 0;
        auto src_p  = obj.if_contains("src_port")  ? obj.at("src_port").as_int64()   : 0;
        auto dst_p  = obj.if_contains("dst_port")  ? obj.at("dst_port").as_int64()   : 0;
        nat_policies.emplace_back(
            std::string(from),
            static_cast<uint32_t>(from_m),
            std::string(to),
            static_cast<uint32_t>(to_m),
            static_cast<std::uint16_t>(src_p),
            static_cast<std::uint16_t>(dst_p)
        );
    }
}

void Config::parseRoutingTable(const boost::json::value& object) {
    if (!object.is_array()) return;
    for (const auto& elem : object.as_array()) {
        if (!elem.is_object()) continue;
        const auto& obj = elem.as_object();
        auto network = obj.if_contains("network") ? obj.at("network").as_string().c_str() : "0.0.0.0";
        auto mask    = obj.if_contains("mask")    ? obj.at("mask").as_string().c_str()    : "0.0.0.0";
        auto gw      = obj.if_contains("gateway") ? obj.at("gateway").as_string().c_str() : "0.0.0.0";
        auto iface   = obj.if_contains("iface")   ? obj.at("iface").as_string().c_str()   : "";
        routing_table.addRoute(
            IPv4Address(std::string(network)),
            IPv4Address(std::string(mask)),
            IPv4Address(std::string(gw)),
            iface
        );
    }
}

void Config::loadMalwareDatabase(const boost::json::value& object) {
    if (object.is_array()) {
        for (const auto& entry : object.as_array()) {
            if (entry.is_string()) {
                malware_hashes.emplace_back(entry.as_string().c_str());
            }
        }
    } else if (object.is_string()) {
        std::ifstream file(object.as_string().c_str());
        std::string line;
        while (std::getline(file, line)) {
            if (!line.empty()) malware_hashes.push_back(line);
        }
    }
}

std::vector<pcpp::PcapLiveDevice*> Config::getCaptureInterfaces() {
    return capture_interfaces;
}

// ------------------------- Policy classes -------------------------

bool Policy::does_match_policy(pcpp::IPv4Layer ipv4_packet) {
    bool src_ip_match = network_from.isContaining(ipv4_packet.getSrcIPAddress());
    bool dst_ip_match = network_to.isContaining(ipv4_packet.getDstIPAddress());

    auto* tcpLayer = ipv4_packet.getNextLayer() != nullptr
                         ? dynamic_cast<pcpp::TcpLayer*>(ipv4_packet.getNextLayer())
                         : nullptr;
    bool src_port_match = source_port == 0;
    bool dst_port_match = destination_port == 0;
    if (tcpLayer != nullptr) {
        src_port_match = source_port == 0 || tcpLayer->getTcpHeader()->portSrc == htons(source_port);
        dst_port_match = destination_port == 0 || tcpLayer->getTcpHeader()->portDst == htons(destination_port);
    }
    return src_ip_match && dst_ip_match && src_port_match && dst_port_match;
}

std::vector<std::shared_ptr<SecurityProfile>> SecurityPolicy::evaluate_security_profiles(
    pcpp::IPv4Layer& ipv4_packet
) {
    if (!does_match_policy(ipv4_packet)) {
        return {};
    }
    return security_profiles;
}

bool SecurityPolicy::getAllowPacket() { return allow_packet; }

// ------------------------- NAT -------------------------

NatState NatPolicy::nat_state(1024, 65535);

void NatPolicy::configureNatState(uint16_t port_start, uint16_t port_end) {
    nat_state = NatState(port_start, port_end);
}

pcpp::IPv4Layer NatPolicy::applyNat(pcpp::IPv4Layer* ipLayer) {
    // For now, simply return a copy of the packet. Actual NAT adjustments would take place here.
    return *ipLayer;
}

Session& NatSessionTable::createSession(SessionFlowKey const& key, NatSession session) {
    auto [it, _] = nat_sessions.emplace(key, std::move(session));
    return it->second;
}

Session* NatSessionTable::findSession(SessionFlowKey const& key) {
    auto it = nat_sessions.find(key);
    if (it == nat_sessions.end()) return nullptr;
    return &it->second;
}

void NatSessionTable::eraseSession(SessionFlowKey const& key) { nat_sessions.erase(key); }

bool NatSessionTable::doesSessionExist(const SessionFlowKey& key) const {
    return nat_sessions.find(key) != nat_sessions.end();
}

std::optional<uint16_t> PortPool::acquire_free_port_number() {
    for (uint16_t i = 0; i < used_.size(); ++i) {
        uint16_t candidate = start_ + ((next_ - start_ + i) % used_.size());
        if (!used_[candidate - start_]) {
            used_[candidate - start_] = true;
            next_ = candidate + 1;
            return candidate;
        }
    }
    return std::nullopt;
}

void PortPool::release_port(uint16_t port) {
    if (port < start_ || port > end_) return;
    used_[port - start_] = false;
}

NatSession* NatState::getOrCreateSession(const SessionFlowKey& key, pcpp::IPv4Address external_ip) {
    if (auto existing = table.findSession(key)) {
        return static_cast<NatSession*>(existing);
    }
    auto port_opt = ports.acquire_free_port_number();
    if (!port_opt.has_value()) {
        return nullptr;
    }
    NatSession session(
        external_ip,
        key.src_ip,
        key.src_port,
        key.dst_ip,
        key.dst_port,
        external_ip,
        port_opt.value(),
        true
    );
    return static_cast<NatSession*>(&table.createSession(key, std::move(session)));
}

void NatState::removeSession(const SessionFlowKey& key) {
    auto* session = dynamic_cast<NatSession*>(table.findSession(key));
    if (session != nullptr) {
        ports.release_port(session->nat_port);
    }
    table.eraseSession(key);
}

// ------------------------- Security Profiles -------------------------

SecurityProfile::SecurityProfile() = default;

DlpProfile::DlpProfile(const std::vector<std::string>& regex_patterns) {
    for (const auto& pattern : regex_patterns) {
        sensitive_data_patterns.emplace_back(pattern, std::regex::icase);
    }
}

Action DlpProfile::scan(const Session& session, pcpp::IPv4Layer /*ipv4_packet*/) {
    auto const* dec_session = dynamic_cast<const DecryptionSession*>(&session);
    std::string data = dec_session != nullptr ? dec_session->getDecryptedDataAsString() : "";
    for (const auto& re : sensitive_data_patterns) {
        if (std::regex_search(data, re)) {
            return BLOCK;
        }
    }
    return ALLOW;
}

AntimalwareProfile::AntimalwareProfile(const std::vector<std::string>& bad_hashes)
    : known_malware_hashes(bad_hashes.begin(), bad_hashes.end()) {}

std::string AntimalwareProfile::calculateSHA256(const uint8_t* data, size_t len) {
    unsigned char hash[EVP_MAX_MD_SIZE];
    unsigned int hash_len = 0;

    EVP_MD_CTX* mdctx = EVP_MD_CTX_new();
    EVP_DigestInit_ex(mdctx, EVP_sha256(), nullptr);
    EVP_DigestUpdate(mdctx, data, len);
    EVP_DigestFinal_ex(mdctx, hash, &hash_len);
    EVP_MD_CTX_free(mdctx);

    std::ostringstream oss;
    for (unsigned int i = 0; i < hash_len; ++i) {
        oss << std::hex << std::setw(2) << std::setfill('0') << static_cast<int>(hash[i]);
    }
    return oss.str();
}

Action AntimalwareProfile::scan(const Session& /*session*/, pcpp::IPv4Layer ipv4_packet) {
    const uint8_t* data = ipv4_packet.getData();
    size_t len = ipv4_packet.getDataLen();
    auto hash = calculateSHA256(data, len);
    if (known_malware_hashes.find(hash) != known_malware_hashes.end()) {
        return BLOCK;
    }
    return ALLOW;
}

UrlFilteringProfile::UrlFilteringProfile(const std::vector<std::string>& domains_to_block)
    : blocked_domains(domains_to_block.begin(), domains_to_block.end()) {}

Action UrlFilteringProfile::scan(const Session& session, pcpp::IPv4Layer /*ipv4_packet*/) {
    auto const* dec_session = dynamic_cast<const DecryptionSession*>(&session);
    std::string payload = dec_session != nullptr ? dec_session->getDecryptedDataAsString() : "";
    for (const auto& domain : blocked_domains) {
        if (payload.find(domain) != std::string::npos) {
            return BLOCK;
        }
    }
    return ALLOW;
}

// ------------------------- Decryption -------------------------

DecryptionProfile::DecryptionProfile(
    std::string name,
    std::string ca_cert,
    std::string ca_key,
    std::string from_ip,
    uint32_t from_mask,
    std::string to_ip,
    uint32_t to_mask
)
    : should_decrypt(true)
    , profile_name(std::move(name))
    , ca_certificate_path(std::move(ca_cert))
    , ca_private_key_path(std::move(ca_key))
    , network_from(std::move(from_ip) + "/" + std::to_string(from_mask))
    , network_to(std::move(to_ip) + "/" + std::to_string(to_mask)) {}

bool DecryptionProfile::loadCryptoMaterial() {
    if (ca_cert != nullptr && ca_private_key != nullptr) return true;

    FILE* cert_file = fopen(ca_certificate_path.c_str(), "r");
    if (cert_file != nullptr) {
        ca_cert = PEM_read_X509(cert_file, nullptr, nullptr, nullptr);
        fclose(cert_file);
    }
    FILE* key_file = fopen(ca_private_key_path.c_str(), "r");
    if (key_file != nullptr) {
        ca_private_key = PEM_read_PrivateKey(key_file, nullptr, nullptr, nullptr);
        fclose(key_file);
    }
    return ca_cert != nullptr && ca_private_key != nullptr;
}

bool DecryptionProfile::shouldDecrypt() { return should_decrypt; }

bool DecryptionProfile::doesMatchProfile(Session const& session) const {
    auto* data = session.getData(); // use to silence unused warnings
    (void)data;
    // For simplicity, match using the stored networks against a placeholder IP of session flows.
    return network_from.isContaining(pcpp::IPv4Address("0.0.0.0")) &&
           network_to.isContaining(pcpp::IPv4Address("0.0.0.0"));
}

uint8_t* DecryptionProfile::decrypt() { return nullptr; }

DecryptionManager::DecryptionManager() : ctx_server(nullptr), ctx_client(nullptr) {}

void DecryptionManager::init() {
    SSL_library_init();
    OpenSSL_add_ssl_algorithms();
    ctx_server = SSL_CTX_new(TLS_method());
    ctx_client = SSL_CTX_new(TLS_method());
}

bool DecryptionManager::processPacket(Session* /*session*/, pcpp::Packet& /*packet*/, std::vector<pcpp::Packet>& /*outPackets*/) {
    return false;
}

void DecryptionManager::decrypt_and_enhance_session(DecryptionSession /*decryption_session*/) {
    // Placeholder for decryption logic
}

SSL* DecryptionManager::createForgedServerSSL(const std::string& /*serverName*/) {
    return SSL_new(ctx_server);
}

// ------------------------- Session -------------------------

Session::Session(
    pcpp::IPv4Address firewall_interface_src_ip,
    pcpp::IPv4Address firewall_interface_dest_ip,
    pcpp::IPv4Address source_ip,
    uint16_t          source_port,
    pcpp::IPv4Address destination_ip,
    uint16_t          destination_port
) {
    source_to_destination = {source_ip, source_port, destination_ip, destination_port};
    destination_to_source = {destination_ip, destination_port, source_ip, source_port};
    session_state = ESTABLISHED;
    (void)firewall_interface_src_ip;
    (void)firewall_interface_dest_ip;
}

SessionFlowKey Session::generateSessionFlowKey(
    pcpp::IPv4Address source_ip,
    uint16_t          source_port,
    pcpp::IPv4Address destination_ip,
    uint16_t          destination_port
) {
    return {source_ip, source_port, destination_ip, destination_port, pcpp::TCP};
}

uint8_t* Session::getData() {
    if (data_buffer.empty()) return nullptr;
    return data_buffer.data();
}

uint8_t Session::getDataLength() { return static_cast<uint8_t>(data_buffer.size()); }

uint8_t Session::appendData(uint8_t* new_data, uint8_t length) {
    data_buffer.insert(data_buffer.end(), new_data, new_data + length);
    return static_cast<uint8_t>(data_buffer.size());
}

DecryptionSession::DecryptionSession(
    pcpp::IPv4Address firewall_interface_ip,
    pcpp::IPv4Address source_ip,
    uint16_t          source_port,
    pcpp::IPv4Address destination_ip,
    uint16_t          destination_port
)
    : Session(
          firewall_interface_ip,
          firewall_interface_ip,
          source_ip,
          source_port,
          destination_ip,
          destination_port
      )
    , seq_num(0)
    , ack_num(0) {}

void DecryptionSession::processEncryptedData(const uint8_t* payload, size_t length) {
    decrypted_buffer.insert(decrypted_buffer.end(), payload, payload + length);
}

bool DecryptionSession::hasCompleteHttpHeader() const {
    const std::string data_str(decrypted_buffer.begin(), decrypted_buffer.end());
    return data_str.find("\r\n\r\n") != std::string::npos;
}

std::string DecryptionSession::getDecryptedDataAsString() const {
    return std::string(decrypted_buffer.begin(), decrypted_buffer.end());
}

void DecryptionSession::clearBuffer() { decrypted_buffer.clear(); }

NatSession::NatSession(
    pcpp::IPv4Address firewall_interface_ip,
    pcpp::IPv4Address source_ip,
    uint16_t          source_port,
    pcpp::IPv4Address destination_ip,
    uint16_t          destination_port,
    pcpp::IPv4Address nat_ip,
    uint16_t nat_port,
    bool is_source_nat
)
    : Session(
          firewall_interface_ip,
          firewall_interface_ip,
          source_ip,
          source_port,
          destination_ip,
          destination_port
      )
    , nat_ip(nat_ip)
    , nat_port(nat_port)
    , is_source_nat(is_source_nat) {}

// ------------------------- Session tables -------------------------

SessionTable::SessionMap SessionTable::sessions_{};

SessionTable::SessionTable() = default;

Session* SessionTable::findSession(SessionFlowKey const& key) {
    auto it = sessions_.find(key);
    if (it == sessions_.end()) return nullptr;
    return &it->second;
}

Session& SessionTable::createSession(SessionFlowKey const& key, Session session) {
    auto [it, _] = sessions_.emplace(key, std::move(session));
    return it->second;
}

void SessionTable::eraseSession(SessionFlowKey const& key) { sessions_.erase(key); }

bool SessionTable::isPacketEndingSession(const pcpp::TcpLayer& tcpLayer) const {
    auto header = tcpLayer.getTcpHeader();
    return header->finFlag || header->rstFlag;
}

bool SessionTable::doesSessionExist(const SessionFlowKey& key) const {
    return sessions_.find(key) != sessions_.end();
}

DecryptionSessionTable::SessionMap DecryptionSessionTable::decryption_sessions{};

Session& DecryptionSessionTable::createSession(SessionFlowKey const& key, DecryptionSession session) {
    std::unique_lock lock(rw_lock);
    auto [it, _] = decryption_sessions.emplace(key, std::move(session));
    return it->second;
}

Session* DecryptionSessionTable::findSession(SessionFlowKey const& key) {
    std::shared_lock lock(rw_lock);
    auto it = decryption_sessions.find(key);
    if (it == decryption_sessions.end()) return nullptr;
    return &it->second;
}

void DecryptionSessionTable::eraseSession(SessionFlowKey const& key) {
    std::unique_lock lock(rw_lock);
    decryption_sessions.erase(key);
}

bool DecryptionSessionTable::doesSessionExist(const SessionFlowKey& key) const {
    std::shared_lock lock(rw_lock);
    return decryption_sessions.find(key) != decryption_sessions.end();
}

// ------------------------- NAT service -------------------------

pcpp::IPv4Layer* NatService::applyNat(NatSession session, pcpp::IPv4Layer* ipLayerPacket) {
    if (session.is_source_nat) {
        ipLayerPacket->setSrcIPAddress(session.nat_ip);
    } else {
        ipLayerPacket->setDstIPAddress(session.nat_ip);
    }
    return ipLayerPacket;
}

// ------------------------- Routing -------------------------

RoutingTable RoutingEngine::routing_table{};

RoutingEngine::RoutingEngine() = default;

void RoutingTable::addRoute(
    const pcpp::IPv4Address& network,
    const pcpp::IPv4Address& mask,
    const pcpp::IPv4Address& gateway,
    const std::string& iface,
    int /*metric*/
) {
    routes.push_back({network, mask, gateway, iface});
}

void RoutingTable::removeRoute(const pcpp::IPv4Address& network, const pcpp::IPv4Address& mask) {
    routes.erase(
        std::remove_if(
            routes.begin(),
            routes.end(),
            [&](const RouteEntry& entry) {
                return entry.network == network && entry.netmask == mask;
            }
        ),
        routes.end()
    );
}

std::optional<RouteEntry> RoutingTable::findRoute(const pcpp::IPv4Address& destinationIP) {
    for (const auto& route : routes) {
        IPv4Network network(route.network, route.netmask);
        if (network.isContaining(destinationIP)) {
            return route;
        }
    }
    return std::nullopt;
}

void RoutingTable::printTable() const {
    for (const auto& route : routes) {
        std::cout << route.network.toString() << "/" << route.netmask.toString()
                  << " via " << route.gateway.toString()
                  << " dev " << route.interfaceName << std::endl;
    }
}

void RoutingEngine::routePacket(pcpp::IPv4Layer* ipLayerPacket, pcpp::IPv4Layer* /*originalIpLayerPacket*/) {
    auto route = routing_table.findRoute(ipLayerPacket->getDstIPAddress());
    if (!route.has_value()) {
        return;
    }
    // In a complete implementation we would transmit via the selected interface.
}

void RoutingEngine::loadInterfaces(std::vector<PcapLiveDevice*> interfaces_param) {
    interfaces = std::move(interfaces_param);
}

// ------------------------- Utilities -------------------------

template <typename Candidate, typename Object>
static bool matchesObject(const Candidate& candidate, Object* object) {
    if constexpr (requires { candidate.doesMatchProfile(*object); }) {
        return candidate.doesMatchProfile(*object);
    } else if constexpr (requires { candidate.does_match_policy(*object); }) {
        return candidate.does_match_policy(*object);
    }
    return false;
}

template <typename C, typename T>
T matchBasedOnObject(C* c, std::vector<T>& data_to_match_object_to) {
    for (auto& entry : data_to_match_object_to) {
        if (matchesObject(entry, c)) {
            return entry;
        }
    }
    if (data_to_match_object_to.empty()) {
        throw std::runtime_error("No elements to match against");
    }
    return data_to_match_object_to.front();
}

template SecurityPolicy matchBasedOnObject<pcpp::IPv4Layer, SecurityPolicy>(
    pcpp::IPv4Layer*,
    std::vector<SecurityPolicy>&
);
template DecryptionProfile matchBasedOnObject<Session, DecryptionProfile>(
    Session*,
    std::vector<DecryptionProfile>&
);
template NatPolicy matchBasedOnObject<Session, NatPolicy>(Session*, std::vector<NatPolicy>&);

SessionFlowKey getSessionFlowKey(const IPv4Layer* ipLayerPacket, const TcpLayer* tcpLayerPacket) {
    auto src_ip = ipLayerPacket->getSrcIPAddress();
    auto dst_ip = ipLayerPacket->getDstIPAddress();
    uint16_t src_port = tcpLayerPacket ? tcpLayerPacket->getSrcPort() : 0;
    uint16_t dst_port = tcpLayerPacket ? tcpLayerPacket->getDstPort() : 0;
    return Session::generateSessionFlowKey(src_ip, src_port, dst_ip, dst_port);
}

Session* createOrGetSession(
    SessionTable& sessionTable,
    const SessionFlowKey& key,
    const IPv4Layer* ipLayerPacket,
    const TcpLayer* tcpLayerPacket,
    PcapLiveDevice* /*captureInterface*/
) {
    if (auto* existing = sessionTable.findSession(key)) {
        return existing;
    }
    Session session(
        ipLayerPacket->getSrcIPAddress(),
        ipLayerPacket->getDstIPAddress(),
        ipLayerPacket->getSrcIPAddress(),
        tcpLayerPacket ? tcpLayerPacket->getSrcPort() : 0,
        ipLayerPacket->getDstIPAddress(),
        tcpLayerPacket ? tcpLayerPacket->getDstPort() : 0
    );
    return &sessionTable.createSession(key, std::move(session));
}

DecryptionSession createOrGetDecryptionSession(
    DecryptionSessionTable& decryptionSessionTable,
    const SessionFlowKey& key,
    Session* session,
    DecryptionProfile /*decryption_profile*/
) {
    if (auto* existing = decryptionSessionTable.findSession(key)) {
        return *static_cast<DecryptionSession*>(existing);
    }
    DecryptionSession decryption_session(
        session->generateSessionFlowKey(key.src_ip, key.src_port, key.dst_ip, key.dst_port).src_ip,
        key.src_ip,
        key.src_port,
        key.dst_ip,
        key.dst_port
    );
    decryptionSessionTable.createSession(key, decryption_session);
    return decryption_session;
}

NatSession createOrGetNatSession(
    NatSessionTable& natSessionTable,
    const SessionFlowKey& key,
    Session* session,
    NatPolicy /*nat_policy*/
) {
    if (auto* existing = natSessionTable.findSession(key)) {
        return *static_cast<NatSession*>(existing);
    }
    NatSession nat_session(
        session->generateSessionFlowKey(key.src_ip, key.src_port, key.dst_ip, key.dst_port).src_ip,
        key.src_ip,
        key.src_port,
        key.dst_ip,
        key.dst_port,
        key.dst_ip,
        key.dst_port,
        true
    );
    natSessionTable.createSession(key, nat_session);
    return nat_session;
}

bool isNotEncryptedSession(Session* session) {
    return session->getDataLength() == 0;
}
