#ifndef BASIC_FIREWALL_CONFIG_H
#define BASIC_FIREWALL_CONFIG_H
#include <vector>
#include <boost/json.hpp>
#include <pcapplusplus/PcapLiveDevice.h>
#include "../policies/SecurityPolicy.h"
#include "../policies/NatPolicy.h"
#include "../decryption/DecryptionProfile.h"
#include "../routing/RoutingTable.h"


/**
 * @brief Firewall configuration loader and storage.
 */
class Config {
public:
    /** @brief Decryption profiles loaded from configuration. */
    std::vector<DecryptionProfile> decryption_profiles;
    /** @brief Security policies loaded from configuration. */
    std::vector<SecurityPolicy> security_policies;
    /** @brief NAT policies loaded from configuration. */
    std::vector<NatPolicy> nat_policies;
    /** @brief Malware hash database entries. */
    std::vector<std::string> malware_hashes;
    /** @brief Routing table configuration. */
    RoutingTable routing_table;
    /** @brief Names of capture interfaces to use. */
    std::vector<std::string> interface_names;
    /** @brief Path to the configuration file. */
    std::pmr::string configuration_file_path;
    /** @brief Whether TLS MITM is enabled. */
    bool tls_mitm_enabled = false;
    /** @brief Port for TLS MITM listener. */
    uint16_t tls_mitm_port = 8443;
    /** @brief Public IP address for NAT operations. */
    pcpp::IPv4Address public_ip_addr;

    /**
     * @brief Construct configuration with a config file path.
     *
     * @param file_path Path to the configuration file.
     */
    Config(std::pmr::string file_path)
        : configuration_file_path(std::move(file_path)) {}

    /**
     * @brief Load configuration from the configured file path.
     */
    void load();
    /**
     * @brief Resolve capture interface objects from interface names.
     *
     * @return Vector of capture interfaces.
     */
    std::vector<pcpp::PcapLiveDevice*> getCaptureInterfaces();
    /**
     * @brief Determine if traffic should be decrypted.
     *
     * @param ipLayer IPv4 layer to evaluate.
     * @return True if a decryption profile matches.
     */
    bool shouldDecryptTraffic(const pcpp::IPv4Layer& ipLayer) const;

private:
    /**
     * @brief Parse a decryption profile JSON object.
     *
     * @param object JSON value representing a decryption profile.
     */
    void parseDecryptionProfile(const boost::json::value& object);
    /**
     * @brief Parse a security policy JSON object.
     *
     * @param object JSON value representing a security policy.
     */
    void parseSecurityPolicy(const boost::json::value& object);
    /**
     * @brief Parse a NAT policy JSON object.
     *
     * @param object JSON value representing a NAT policy.
     */
    void parseNatPolicy(const boost::json::value& object);
    /**
     * @brief Parse routing table entries from JSON.
     *
     * @param object JSON value representing routing configuration.
     */
    void parseRoutingTable(const boost::json::value& object);
    /**
     * @brief Parse TLS MITM configuration settings.
     *
     * @param object JSON value representing TLS MITM configuration.
     */
    void parseTlsMitm(const boost::json::value& object);
    /**
     * @brief Load and parse configuration from a file path.
     *
     * @param filepath File path to load.
     */
    void loadFromFile(const std::string& filepath);
    /**
     * @brief Parse interface names from JSON.
     *
     * @param object JSON value representing interface list.
     */
    void parseInterfaces(const boost::json::value& object);
    /**
     * @brief Load malware hash list from JSON.
     *
     * @param object JSON value representing malware hashes.
     */
    void loadMalwareDatabase(const boost::json::value& object);
};
#endif
