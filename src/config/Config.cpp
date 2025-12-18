#include <fstream>
#include <sstream>
#include <utility>
#include <memory>
#include <boost/json.hpp>
#include "../../include/configuration/Config.h"
#include "../../include/policies/Policy.h"

using namespace pcpp;

namespace {
std::string toStdString(const std::pmr::string& pmr) {
    return std::string(pmr.begin(), pmr.end());
}
}

void Config::load() {
    loadFromFile(toStdString(configuration_file_path));
}

void Config::loadFromFile(const std::string& filepath) {
    std::ifstream file(filepath);
    if (!file.is_open()) {
        throw std::runtime_error("Unable to open configuration file: " + filepath);
    }

    std::stringstream buffer;
    buffer << file.rdbuf();
    auto json_value = boost::json::parse(buffer.str());
    if (!json_value.is_object()) return;
    const auto& root = json_value.as_object();

    if (auto it = root.find("interfaces"); it != root.end()) {
        parseInterfaces(it->value());
    }
    if (auto it = root.find("decryption_profiles"); it != root.end()) {
        parseDecryptionProfile(it->value());
    }
    if (auto it = root.find("security_policies"); it != root.end()) {
        parseSecurityPolicy(it->value());
    }
    if (auto it = root.find("nat_policies"); it != root.end()) {
        parseNatPolicy(it->value());
    }
    if (auto it = root.find("routing"); it != root.end()) {
        parseRoutingTable(it->value());
    }
    if (auto it = root.find("malware_db"); it != root.end()) {
        loadMalwareDatabase(it->value());
    }
}

void Config::parseInterfaces(const boost::json::value& object) {
    if (!object.is_object()) return;
    for (const auto& [_, iface] : object.as_object()) {
        if (!iface.is_string()) continue;
        auto* device = PcapLiveDeviceList::getInstance().getPcapLiveDeviceByName(iface.as_string().c_str());
        if (device != nullptr) {
            capture_interfaces.push_back(device);
        }
    }
}

void Config::parseDecryptionProfile(const boost::json::value& object) {
    if (!object.is_array()) return;
    for (const auto& entry : object.as_array()) {
        if (!entry.is_object()) continue;
        const auto& obj = entry.as_object();
        std::string name = obj.if_contains("name") ? obj.at("name").as_string().c_str() : "";
        std::string ca = obj.if_contains("ca") ? obj.at("ca").as_string().c_str() : "";
        std::string key = obj.if_contains("key") ? obj.at("key").as_string().c_str() : "";
        std::string from = obj.if_contains("from") ? obj.at("from").as_string().c_str() : "0.0.0.0";
        std::string to = obj.if_contains("to") ? obj.at("to").as_string().c_str() : "0.0.0.0";
        uint32_t from_mask = obj.if_contains("from_mask") ? static_cast<uint32_t>(obj.at("from_mask").as_int64()) : 0;
        uint32_t to_mask = obj.if_contains("to_mask") ? static_cast<uint32_t>(obj.at("to_mask").as_int64()) : 0;
        decryption_profiles.emplace_back(name, ca, key, from, from_mask, to, to_mask);
    }
}

void Config::parseSecurityPolicy(const boost::json::value& object) {
    if (!object.is_array()) return;
    for (const auto& entry : object.as_array()) {
        if (!entry.is_object()) continue;
        const auto& obj = entry.as_object();
        std::pmr::string from = obj.if_contains("from") ? std::pmr::string(obj.at("from").as_string().c_str()) : "0.0.0.0";
        std::pmr::string to = obj.if_contains("to") ? std::pmr::string(obj.at("to").as_string().c_str()) : "0.0.0.0";
        uint32_t from_mask = obj.if_contains("from_mask") ? static_cast<uint32_t>(obj.at("from_mask").as_int64()) : 0;
        uint32_t to_mask = obj.if_contains("to_mask") ? static_cast<uint32_t>(obj.at("to_mask").as_int64()) : 0;
        uint16_t src_port = obj.if_contains("src_port") ? static_cast<uint16_t>(obj.at("src_port").as_int64()) : 0;
        uint16_t dst_port = obj.if_contains("dst_port") ? static_cast<uint16_t>(obj.at("dst_port").as_int64()) : 0;
        bool allow = obj.if_contains("allow") ? obj.at("allow").as_bool() : true;
        security_policies.emplace_back(
            std::move(from),
            from_mask,
            std::move(to),
            to_mask,
            src_port,
            dst_port,
            allow,
            std::vector<std::shared_ptr<SecurityProfile>>{}
        );
    }
}

void Config::parseNatPolicy(const boost::json::value& object) {
    if (!object.is_array()) return;
    for (const auto& entry : object.as_array()) {
        if (!entry.is_object()) continue;
        const auto& obj = entry.as_object();
        std::pmr::string from = obj.if_contains("from") ? std::pmr::string(obj.at("from").as_string().c_str()) : "0.0.0.0";
        std::pmr::string to = obj.if_contains("to") ? std::pmr::string(obj.at("to").as_string().c_str()) : "0.0.0.0";
        uint32_t from_mask = obj.if_contains("from_mask") ? static_cast<uint32_t>(obj.at("from_mask").as_int64()) : 0;
        uint32_t to_mask = obj.if_contains("to_mask") ? static_cast<uint32_t>(obj.at("to_mask").as_int64()) : 0;
        uint16_t src_port = obj.if_contains("src_port") ? static_cast<uint16_t>(obj.at("src_port").as_int64()) : 0;
        uint16_t dst_port = obj.if_contains("dst_port") ? static_cast<uint16_t>(obj.at("dst_port").as_int64()) : 0;
        nat_policies.emplace_back(std::move(from), from_mask, std::move(to), to_mask, src_port, dst_port);
    }
}

void Config::parseRoutingTable(const boost::json::value& object) {
    if (!object.is_array()) return;
    for (const auto& entry : object.as_array()) {
        if (!entry.is_object()) continue;
        const auto& obj = entry.as_object();
        auto network = obj.if_contains("network") ? obj.at("network").as_string().c_str() : "0.0.0.0";
        auto mask = obj.if_contains("mask") ? obj.at("mask").as_string().c_str() : "0.0.0.0";
        auto gateway = obj.if_contains("gateway") ? obj.at("gateway").as_string().c_str() : "0.0.0.0";
        auto iface = obj.if_contains("iface") ? obj.at("iface").as_string().c_str() : "";
        routing_table.addRoute(IPv4Address(network), IPv4Address(mask), IPv4Address(gateway), iface);
    }
}

void Config::loadMalwareDatabase(const boost::json::value& object) {
    if (object.is_array()) {
        for (const auto& val : object.as_array()) {
            if (val.is_string()) malware_hashes.emplace_back(val.as_string().c_str());
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
