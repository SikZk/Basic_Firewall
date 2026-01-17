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
        std::cout << "[Config] No NAT policies configured." << std::endl;
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
    if (!object.is_array()) {
        return;
    }
    nat_policies.clear();
    for (const auto& entry : object.as_array()) {
        if (!entry.is_object()) {
            continue;
        }
        const auto& obj = entry.as_object();
        if (!obj.contains("from") || !obj.contains("to")) {
            continue;
        }
        auto network_from = std::string(obj.at("from").as_string());
        auto network_to = std::string(obj.at("to").as_string());
        uint32_t from_mask = obj.contains("from_mask") ? static_cast<uint32_t>(obj.at("from_mask").to_number<int64_t>()) : 0;
        uint32_t to_mask = obj.contains("to_mask") ? static_cast<uint32_t>(obj.at("to_mask").to_number<int64_t>()) : 0;
        uint16_t src_port = obj.contains("src_port") ? static_cast<uint16_t>(obj.at("src_port").to_number<int64_t>()) : 0;
        uint16_t dst_port = obj.contains("dst_port") ? static_cast<uint16_t>(obj.at("dst_port").to_number<int64_t>()) : 0;
        nat_policies.emplace_back(
            std::move(network_from),
            from_mask,
            std::move(network_to),
            to_mask,
            src_port,
            dst_port
        );
    }
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
    if (obj.contains("nat_policies")) {
        parseNatPolicy(obj.at("nat_policies"));
    }
    if (obj.contains("nat_port_pool")) {
        const auto& pool = obj.at("nat_port_pool");
        if (pool.is_object()) {
            const auto& pool_obj = pool.as_object();
            if (pool_obj.contains("start") && pool_obj.contains("end")) {
                uint16_t start = static_cast<uint16_t>(pool_obj.at("start").to_number<int64_t>());
                uint16_t end = static_cast<uint16_t>(pool_obj.at("end").to_number<int64_t>());
                NatPolicy::configureNatState(start, end);
            }
        }
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
