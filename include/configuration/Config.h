#ifndef BASIC_FIREWALL_CONFIG_H
#define BASIC_FIREWALL_CONFIG_H
#include <vector>
#include <boost/json/src.hpp>
#include "../policies/SecurityPolicy.h"
#include "../policies/NatPolicy.h"
#include "../decryption/DecryptionProfile.h"
#include "../routing/RoutingTable.h"


class Config {
    public:
        std::vector<DecryptionProfile> decryption_profiles;
        std::vector<SecurityPolicy> security_policies;
        std::vector<NatPolicy> nat_policies;
        RoutingTable routing_table;
        std::pmr::string configuration_file_path;

        Config(std::pmr::string file_path)
            : configuration_file_path(std::move(file_path)) {};

        void load();

        std::vector<pcpp::PcapLiveDevice*> getCaptureInterfaces();
    private:
        // pamiętajmy aby dodać tutaj na końcu profilu decryption_profile.should_decrypt = false; dla wszystkich sesji
        void parseDecryptionProfile(const boost::json::value& object);
        // pamiętajmy żeby tutaj po zparsowaniu zawsze dodać na samym końcu DENY from any to any
        void parseSecurityPolicy(const boost::json::value& object);
        void parseNatPolicy(const boost::json::value& object);
        void parseRoutingTable(const boost::json::value& object);
        void loadFromFile(const std::string& filepath);
        void parseInterfaces(const boost::json::value& object);

};
#endif