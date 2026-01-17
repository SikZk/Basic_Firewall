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
    if (!object.is_object()) {
        return;
    }

    const auto& obj = object.as_object();
    if (obj.contains("port_pool") && obj.at("port_pool").is_object()) {
        const auto& pool = obj.at("port_pool").as_object();
        uint16_t start = 10000;
        uint16_t end = 20000;
        if (pool.contains("start") && pool.at("start").is_int64()) {
            start = static_cast<uint16_t>(pool.at("start").as_int64());
        }
        if (pool.contains("end") && pool.at("end").is_int64()) {
            end = static_cast<uint16_t>(pool.at("end").as_int64());
        }
        NatPolicy::configureNatState(start, end);
    }

    if (!obj.contains("policies") || !obj.at("policies").is_array()) {
        return;
    }

    nat_policies.clear();
    for (const auto& entry : obj.at("policies").as_array()) {
        if (!entry.is_object()) {
            continue;
        }
        const auto& policy_obj = entry.as_object();

        auto from_network = std::string(policy_obj.at("from").as_string());
        auto to_network = std::string(policy_obj.at("to").as_string());
        uint32_t from_mask = static_cast<uint32_t>(policy_obj.at("from_mask").as_int64());
        uint32_t to_mask = static_cast<uint32_t>(policy_obj.at("to_mask").as_int64());

        std::uint16_t src_port = 0;
        std::uint16_t dest_port = 0;
        if (policy_obj.contains("src_port") && policy_obj.at("src_port").is_int64()) {
            src_port = static_cast<uint16_t>(policy_obj.at("src_port").as_int64());
        }
        if (policy_obj.contains("dest_port") && policy_obj.at("dest_port").is_int64()) {
            dest_port = static_cast<uint16_t>(policy_obj.at("dest_port").as_int64());
        }

        NatType type = NatType::Source;
        if (policy_obj.contains("type") && policy_obj.at("type").is_string()) {
            const auto type_str = std::string(policy_obj.at("type").as_string());
            if (type_str == "destination") {
                type = NatType::Destination;
            }
        }

        std::string translated_source_ip = "0.0.0.0";
        std::string translated_destination_ip = "0.0.0.0";

        if (policy_obj.contains("translated_source_ip") && policy_obj.at("translated_source_ip").is_string()) {
            translated_source_ip = std::string(policy_obj.at("translated_source_ip").as_string());
        }
        if (policy_obj.contains("translated_destination_ip") && policy_obj.at("translated_destination_ip").is_string()) {
            translated_destination_ip = std::string(policy_obj.at("translated_destination_ip").as_string());
        }

        nat_policies.emplace_back(
            from_network,
            from_mask,
            to_network,
            to_mask,
            src_port,
            dest_port,
            type,
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
    if (obj.contains("nat")) {
        parseNatPolicy(obj.at("nat"));
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
