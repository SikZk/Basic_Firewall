#include "../../include/decryption/DecryptionProfile.h"
#include <iostream>
#include <openssl/pem.h>
#include <cstdio>
#include <arpa/inet.h>

namespace {
uint32_t prefixToMask(uint32_t prefix)
{
    if (prefix == 0) {
        return 0;
    }
    return htonl(0xFFFFFFFFu << (32 - prefix));
}

bool isInSubnet(const pcpp::IPv4Address& ip, const pcpp::IPv4Address& network, uint32_t prefix)
{
    if (prefix == 0) {
        return true;
    }
    uint32_t mask = prefixToMask(prefix);
    return (ip.toInt() & mask) == (network.toInt() & mask);
}
} // namespace

DecryptionProfile::DecryptionProfile(std::string name,
                                     std::string ca_cert,
                                     std::string ca_key,
                                     std::string from_ip,
                                     uint32_t from_mask,
                                     std::string to_ip,
                                     uint32_t to_mask)
    : should_decrypt(false),
      profile_name(std::move(name)),
      ca_certificate_path(std::move(ca_cert)),
      ca_private_key_path(std::move(ca_key)),
      network_from_address(pcpp::IPv4Address(std::move(from_ip))),
      network_from_mask(from_mask),
      network_to_address(pcpp::IPv4Address(std::move(to_ip))),
      network_to_mask(to_mask)
{
}

bool DecryptionProfile::loadCryptoMaterial()
{
    if (ca_certificate_path.empty() || ca_private_key_path.empty()) {
        std::cout << "[DecryptionProfile] Missing CA certificate or private key path for profile: "
                  << profile_name << std::endl;
        return false;
    }

    FILE* cert_file = std::fopen(ca_certificate_path.c_str(), "r");
    if (!cert_file) {
        std::cout << "[DecryptionProfile] Failed to open CA certificate: "
                  << ca_certificate_path << std::endl;
        return false;
    }
    X509* loaded_cert = PEM_read_X509(cert_file, nullptr, nullptr, nullptr);
    std::fclose(cert_file);
    if (!loaded_cert) {
        std::cout << "[DecryptionProfile] Failed to read CA certificate: "
                  << ca_certificate_path << std::endl;
        return false;
    }

    FILE* key_file = std::fopen(ca_private_key_path.c_str(), "r");
    if (!key_file) {
        X509_free(loaded_cert);
        std::cout << "[DecryptionProfile] Failed to open CA private key: "
                  << ca_private_key_path << std::endl;
        return false;
    }
    EVP_PKEY* loaded_key = PEM_read_PrivateKey(key_file, nullptr, nullptr, nullptr);
    std::fclose(key_file);
    if (!loaded_key) {
        X509_free(loaded_cert);
        std::cout << "[DecryptionProfile] Failed to read CA private key: "
                  << ca_private_key_path << std::endl;
        return false;
    }

    ca_cert = loaded_cert;
    ca_private_key = loaded_key;
    std::cout << "[DecryptionProfile] Loaded CA material for profile: " << profile_name << std::endl;
    return true;
}

bool DecryptionProfile::shouldDecrypt()
{
    return should_decrypt;
}

bool DecryptionProfile::doesMatchProfile(Session const& session) const
{
    const auto& forward = session.getSourceToDestinationFlow();
    if (isInSubnet(forward.internal_ip, network_from_address, network_from_mask) &&
        isInSubnet(forward.external_ip, network_to_address, network_to_mask)) {
        return true;
    }

    const auto& reverse = session.getDestinationToSourceFlow();
    return isInSubnet(reverse.internal_ip, network_from_address, network_from_mask) &&
           isInSubnet(reverse.external_ip, network_to_address, network_to_mask);
}

uint8_t* DecryptionProfile::decrypt()
{
    return nullptr;
}
