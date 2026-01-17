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
    if (!object.is_array()) {
        return;
    }
    nat_policies.clear();
    for (const auto& entry : object.as_array()) {
        if (!entry.is_object()) {
            continue;
        }
        const auto& obj = entry.as_object();
        if (!obj.contains("from") || !obj.contains("to") ||
            !obj.contains("from_mask") || !obj.contains("to_mask")) {
            continue;
        }
        const auto from = std::string(obj.at("from").as_string());
        const auto to = std::string(obj.at("to").as_string());
        const auto from_mask = static_cast<uint32_t>(obj.at("from_mask").as_int64());
        const auto to_mask = static_cast<uint32_t>(obj.at("to_mask").as_int64());
        const auto src_port = obj.contains("src_port") ? static_cast<uint16_t>(obj.at("src_port").as_int64()) : 0;
        const auto dst_port = obj.contains("dst_port") ? static_cast<uint16_t>(obj.at("dst_port").as_int64()) : 0;
        const auto translated_source_ip = obj.contains("translated_source_ip")
            ? std::string(obj.at("translated_source_ip").as_string())
            : "0.0.0.0";
        const auto translated_destination_ip = obj.contains("translated_destination_ip")
            ? std::string(obj.at("translated_destination_ip").as_string())
            : "0.0.0.0";

        nat_policies.emplace_back(
            from,
            from_mask,
            to,
            to_mask,
            src_port,
            dst_port,
            translated_source_ip,
            translated_destination_ip
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
