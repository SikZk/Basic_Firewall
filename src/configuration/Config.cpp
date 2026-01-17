#include "../../include/configuration/Config.h"
#include <pcapplusplus/PcapLiveDeviceList.h>
#include <fstream>
#include <boost/json/src.hpp>
#include <iostream>
#include <sstream>

void Config::load()
{
    loadFromFile("../resources/config.json");

    if (security_policies.empty()) {
        security_policies.emplace_back(
            "0.0.0.0",
            0,
            "0.0.0.0",
            0,
            0,
            0,
            true,
            std::vector<std::shared_ptr<SecurityProfile>>{}
        );
    }

    if (decryption_profiles.empty()) {
        decryption_profiles.emplace_back(
            "default",
            "",
            "",
            "0.0.0.0",
            0,
            "0.0.0.0",
            0
        );
    }

    if (nat_policies.empty()) {
        nat_policies.emplace_back(
            "0.0.0.0",
            0,
            "0.0.0.0",
            0,
            0,
            0
        );
    }
}

std::vector<pcpp::PcapLiveDevice*> Config::getCaptureInterfaces()
{
    std::vector<pcpp::PcapLiveDevice*> vector;
    for (const auto& iface : interface_names) {
        if (auto* device = pcpp::PcapLiveDeviceList::getInstance().getDeviceByName(iface); device != nullptr) {
            vector.push_back(device);
        }
    }

    return vector;
}

void Config::parseDecryptionProfile(const boost::json::value& object)
{
    (void)object;
    std::cout << "[Config] Skipping decryption profile parsing (no-op)." << std::endl;
};
void Config::parseSecurityPolicy(const boost::json::value& object)
{
    (void)object;
    std::cout << "[Config] Skipping security policy parsing (no-op)." << std::endl;
};
void Config::parseNatPolicy(const boost::json::value& object)
{
    (void)object;
    std::cout << "[Config] Skipping NAT policy parsing (no-op)." << std::endl;
};
void Config::parseRoutingTable(const boost::json::value& object)
{
    if (!object.is_array()) {
        return;
    }
    for (const auto& entry : object.as_array()) {
        if (!entry.is_object()) {
            continue;
        }
        const auto& obj = entry.as_object();
        auto network = std::string(obj.at("network").as_string());
        auto mask = std::string(obj.at("mask").as_string());
        auto gateway = std::string(obj.at("gateway").as_string());
        auto iface = std::string(obj.at("interface").as_string());
        routing_table.addRoute(
            pcpp::IPv4Address(network),
            pcpp::IPv4Address(mask),
            pcpp::IPv4Address(gateway),
            iface
        );
    }
};
void Config::loadFromFile(const std::string& filepath)
{
    std::ifstream file(filepath);
    if (!file.is_open()) {
        std::cerr << "[Config] Failed to open config file: " << filepath << std::endl;
        return;
    }
    std::stringstream buffer;
    buffer << file.rdbuf();
    auto data = boost::json::parse(buffer.str());

    if (!data.is_object()) {
        return;
    }
    const auto& obj = data.as_object();
    if (obj.contains("interfaces")) {
        parseInterfaces(obj.at("interfaces"));
    }
    if (obj.contains("routes")) {
        parseRoutingTable(obj.at("routes"));
    }
};
void Config::parseInterfaces(const boost::json::value& object)
{
    if (!object.is_object()) {
        return;
    }
    interface_names.clear();
    for (const auto& item : object.as_object()) {
        interface_names.emplace_back(item.value().as_string());
    }
};
void Config::loadMalwareDatabase(const boost::json::value& object)
{
    (void)object;
    std::cout << "[Config] Skipping malware DB load (no-op)." << std::endl;
};
