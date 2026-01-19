#include "../../include/configuration/Config.h"
#include <pcapplusplus/PcapLiveDeviceList.h>
#include <fstream>
#include <boost/json/src.hpp>
#include <iostream>
#include <sstream>
#include <algorithm>
#include <cctype>

void Config::load()
{
    loadFromFile("../resources/config.json");

    // Zabezpieczenie: jeśli w pliku nie było profili deszyfracji, dodaj domyślny,
    // żeby program się nie wywalił.
    if (decryption_profiles.empty()) {
        decryption_profiles.emplace_back(
            "default", "", "", "0.0.0.0", 0, "0.0.0.0", 0
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
    if (!object.is_array()) return;

    for (const auto& entry : object.as_array()) {
        if (!entry.is_object()) continue;
        const auto& obj = entry.as_object();

        std::string name = obj.at("name").as_string().c_str();
        std::string ca_cert = obj.at("ca_certificate_path").as_string().c_str();
        std::string ca_key = obj.at("ca_private_key_path").as_string().c_str();
        std::string src_net = obj.at("src_network").as_string().c_str();
        uint32_t src_mask = obj.at("src_mask").as_int64();
        std::string dst_net = obj.at("dest_network").as_string().c_str();
        uint32_t dst_mask = obj.at("dest_mask").as_int64();

        DecryptionProfile profile(
            name,
            ca_cert,
            ca_key,
            src_net,
            src_mask,
            dst_net,
            dst_mask
        );
        profile.should_decrypt = profile.loadCryptoMaterial();
        decryption_profiles.emplace_back(std::move(profile));
    }
}

// --- Parsowanie Security Policy z JSON ---
void Config::parseSecurityPolicy(const boost::json::value& object)
{
    if (!object.is_array()) return;

    for (const auto& entry : object.as_array()) {
        if (!entry.is_object()) continue;
        const auto& obj = entry.as_object();

        std::string src_net = obj.at("src_network").as_string().c_str();
        uint32_t src_mask = obj.at("src_mask").as_int64();
        std::string dst_net = obj.at("dest_network").as_string().c_str();
        uint32_t dst_mask = obj.at("dest_mask").as_int64();
        uint16_t src_port = static_cast<uint16_t>(obj.at("src_port").as_int64());
        uint16_t dst_port = static_cast<uint16_t>(obj.at("dest_port").as_int64());

        std::string action_str = "deny";
        if (auto it = obj.find("action"); it != obj.end() && it->value().is_string()) {
            action_str = std::string(it->value().as_string());
        }
        std::transform(action_str.begin(), action_str.end(), action_str.begin(), [](unsigned char ch) {
            return static_cast<char>(std::tolower(ch));
        });

        SecurityPolicy::Action action = SecurityPolicy::Action::Deny;
        if (action_str == "allow") {
            action = SecurityPolicy::Action::Allow;
        }

        security_policies.emplace_back(
            src_net,
            src_mask,
            dst_net,
            dst_mask,
            src_port,
            dst_port,
            action,
            std::vector<std::shared_ptr<SecurityProfile>>{}
        );
    }

    security_policies.emplace_back(
        "0.0.0.0",
        0,
        "0.0.0.0",
        0,
        0,
        0,
        SecurityPolicy::Action::Deny,
        std::vector<std::shared_ptr<SecurityProfile>>{}
    );
}

// --- Parsowanie NAT Policy z JSON ---
void Config::parseNatPolicy(const boost::json::value& object) {
    if (!object.is_array()) return;

    for (const auto& entry : object.as_array()) {
        if (!entry.is_object()) continue;
        const auto& obj = entry.as_object();

        std::string src_net = obj.at("src_network").as_string().c_str();
        uint32_t src_mask = obj.at("src_mask").as_int64();
        std::string dst_net = obj.at("dest_network").as_string().c_str();
        uint32_t dst_mask = obj.at("dest_mask").as_int64();
        uint16_t src_port = (uint16_t)obj.at("src_port").as_int64();
        uint16_t dst_port = (uint16_t)obj.at("dest_port").as_int64();

        nat_policies.emplace_back(
            src_net, src_mask, dst_net, dst_mask, src_port, dst_port
        );
    }
};

void Config::parseRoutingTable(const boost::json::value& object)
{
    if (!object.is_array()) return;
    for (const auto& entry : object.as_array()) {
        if (!entry.is_object()) continue;
        const auto& obj = entry.as_object();
        routing_table.addRoute(
            pcpp::IPv4Address(std::string(obj.at("network").as_string())),
            pcpp::IPv4Address(std::string(obj.at("mask").as_string())),
            pcpp::IPv4Address(std::string(obj.at("gateway").as_string())),
            std::string(obj.at("interface").as_string())
        );
    }
};

void Config::parseTlsMitm(const boost::json::value& object)
{
    if (!object.is_object()) return;
    const auto& obj = object.as_object();
    if (auto it = obj.find("enabled"); it != obj.end() && it->value().is_bool()) {
        tls_mitm_enabled = it->value().as_bool();
    }
    if (auto it = obj.find("listen_port"); it != obj.end() && it->value().is_int64()) {
        tls_mitm_port = static_cast<uint16_t>(it->value().as_int64());
    }
}

void Config::parseUrlFilteringPolicy(const boost::json::value& object)
{
    if (!object.is_array()) return;

    for (const auto& entry : object.as_array()) {
        if (!entry.is_object()) continue;
        const auto& obj = entry.as_object();

        std::string src_net = obj.at("src_network").as_string().c_str();
        uint32_t src_mask = obj.at("src_mask").as_int64();
        std::string dst_net = obj.at("dest_network").as_string().c_str();
        uint32_t dst_mask = obj.at("dest_mask").as_int64();
        uint16_t src_port = static_cast<uint16_t>(obj.at("src_port").as_int64());
        uint16_t dst_port = static_cast<uint16_t>(obj.at("dest_port").as_int64());

        std::vector<std::string> blocked_urls;
        if (auto it = obj.find("blocked_urls"); it != obj.end() && it->value().is_array()) {
            for (const auto& url_entry : it->value().as_array()) {
                if (url_entry.is_string()) {
                    blocked_urls.emplace_back(url_entry.as_string().c_str());
                }
            }
        } else if (auto it = obj.find("urls"); it != obj.end() && it->value().is_array()) {
            for (const auto& url_entry : it->value().as_array()) {
                if (url_entry.is_string()) {
                    blocked_urls.emplace_back(url_entry.as_string().c_str());
                }
            }
        }

        url_filtering_policies.emplace_back(
            src_net,
            src_mask,
            dst_net,
            dst_mask,
            src_port,
            dst_port,
            std::move(blocked_urls)
        );
    }
}

void Config::loadFromFile(const std::string& filepath)
{
    std::ifstream file(filepath);
    if (!file.is_open()) {
        std::cerr << "[Config] Failed to open config file: " << filepath << std::endl;
        return;
    }
    std::stringstream buffer;
    buffer << file.rdbuf();

    try {
        auto data = boost::json::parse(buffer.str());
        if (!data.is_object()) return;
        const auto& obj = data.as_object();

        if (obj.contains("interfaces")) parseInterfaces(obj.at("interfaces"));
        if (obj.contains("routes")) parseRoutingTable(obj.at("routes"));
        // Dodane parsowanie nowych sekcji
        if (obj.contains("nat_policies")) parseNatPolicy(obj.at("nat_policies"));
        if (obj.contains("security_policies")) parseSecurityPolicy(obj.at("security_policies"));
        if (obj.contains("decryption_profiles")) parseDecryptionProfile(obj.at("decryption_profiles"));
        if (obj.contains("url_filtering_policies")) parseUrlFilteringPolicy(obj.at("url_filtering_policies"));
        if (obj.contains("tls_mitm")) parseTlsMitm(obj.at("tls_mitm"));


    } catch (...) {}
};

void Config::parseInterfaces(const boost::json::value& object)
{
    if (!object.is_object()) return;
    interface_names.clear();
    for (const auto& item : object.as_object()) {
        interface_names.emplace_back(item.value().as_string());
    }
    // Zabezpieczenie: upewnij się, że ens34 jest na liście, jeśli user zapomni
    bool hasEns34 = false;
    for(const auto& s : interface_names) if(s == "ens34") hasEns34 = true;
    if(!hasEns34) interface_names.push_back("ens34");
};

void Config::loadMalwareDatabase(const boost::json::value& object) { (void)object; };
