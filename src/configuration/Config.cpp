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

        auto from_obj = obj.at("from").as_object();
        auto to_obj = obj.at("to").as_object();
        const auto& from_net = from_obj.at("network").as_string();
        const auto& to_net   = to_obj.at("network").as_string();

        std::pmr::string network_from{from_net.data(), from_net.size()};
        std::pmr::string network_to  {to_net.data(),   to_net.size()};

        auto parseMask = [](const boost::json::value& value) -> uint32_t {
            if (value.is_int64()) {
                return static_cast<uint32_t>(value.as_int64());
            }
            if (value.is_uint64()) {
                return static_cast<uint32_t>(value.as_uint64());
            }
            if (value.is_string()) {
                const auto mask_str = std::string(value.as_string());
                if (mask_str.find('.') != std::string::npos) {
                    std::istringstream ss(mask_str);
                    std::string octet;
                    uint32_t mask = 0;
                    while (std::getline(ss, octet, '.')) {
                        mask = (mask << 8) + static_cast<uint32_t>(std::stoi(octet));
                    }
                    uint32_t bits = 0;
                    while (mask) {
                        bits += mask & 1u;
                        mask >>= 1u;
                    }
                    return bits;
                }
                return static_cast<uint32_t>(std::stoi(mask_str));
            }
            return 0;
        };

        uint32_t from_mask = parseMask(from_obj.at("mask"));
        uint32_t to_mask = parseMask(to_obj.at("mask"));
        uint16_t src_port = 0;
        uint16_t dest_port = 0;
        if (obj.contains("src_port")) {
            src_port = static_cast<uint16_t>(obj.at("src_port").as_int64());
        }
        if (obj.contains("dest_port")) {
            dest_port = static_cast<uint16_t>(obj.at("dest_port").as_int64());
        }

        std::pmr::string translated_source_ip = "0.0.0.0";
        std::pmr::string translated_destination_ip = "0.0.0.0";
        if (obj.contains("translated_source_ip")) {
            translated_source_ip = std::string(obj.at("translated_source_ip").as_string());
        }
        if (obj.contains("translated_destination_ip")) {
            translated_destination_ip = std::string(obj.at("translated_destination_ip").as_string());
        }

        bool source_nat = obj.if_contains("source_nat")
            ? obj.at("source_nat").as_bool()
            : translated_source_ip != "0.0.0.0";
        bool destination_nat = obj.if_contains("destination_nat")
            ? obj.at("destination_nat").as_bool()
            : translated_destination_ip != "0.0.0.0";

        nat_policies.emplace_back(
            network_from,
            from_mask,
            network_to,
            to_mask,
            src_port,
            dest_port,
            translated_source_ip,
            translated_destination_ip,
            source_nat,
            destination_nat
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
    if (obj.contains("nat")) {
        const auto& nat_obj = obj.at("nat");
        if (nat_obj.is_object()) {
            const auto& nat_settings = nat_obj.as_object();
            if (nat_settings.contains("port_pool")) {
                const auto& pool_obj = nat_settings.at("port_pool").as_object();
                uint16_t start = static_cast<uint16_t>(pool_obj.at("start").as_int64());
                uint16_t end = static_cast<uint16_t>(pool_obj.at("end").as_int64());
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
