#ifndef BASIC_FIREWALL_CONFIG_H
#define BASIC_FIREWALL_CONFIG_H
#include <vector>
#include <boost/json.hpp>
#include <pcapplusplus/PcapLiveDevice.h>
#include "../policies/SecurityPolicy.h"
#include "../policies/NatPolicy.h"
#include "../decryption/DecryptionProfile.h"
#include "../routing/RoutingTable.h"


class Config {
public:
    std::vector<DecryptionProfile> decryption_profiles;
    std::vector<SecurityPolicy> security_policies;
    std::vector<NatPolicy> nat_policies;
    std::vector<std::string> malware_hashes;
    RoutingTable routing_table;
    std::vector<std::string> interface_names;
    std::pmr::string configuration_file_path;
    bool tls_mitm_enabled = false;
    uint16_t tls_mitm_port = 8443;
    pcpp::IPv4Address public_ip_addr;

    Config(std::pmr::string file_path)
        : configuration_file_path(std::move(file_path)) {}

    void load();
    std::vector<pcpp::PcapLiveDevice*> getCaptureInterfaces();
    bool shouldDecryptTraffic(const pcpp::IPv4Layer& ipLayer) const;

private:
    void parseDecryptionProfile(const boost::json::value& object);
    void parseSecurityPolicy(const boost::json::value& object);
    void parseNatPolicy(const boost::json::value& object);
    void parseRoutingTable(const boost::json::value& object);
    void parseTlsMitm(const boost::json::value& object);
    void loadFromFile(const std::string& filepath);
    void parseInterfaces(const boost::json::value& object);
    void loadMalwareDatabase(const boost::json::value& object);
};
#endif
