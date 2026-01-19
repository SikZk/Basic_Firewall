#include "../../include/decryption/DecryptionProfile.h"
#include <iostream>
#include <openssl/pem.h>
#include <arpa/inet.h>

namespace {

bool matchesNetwork(const pcpp::IPv4Address& address, const pcpp::IPv4Address& network, uint32_t maskBits)
{
    if (maskBits == 0) {
        return true;
    }
    if (maskBits > 32) {
        maskBits = 32;
    }

    uint8_t addrBytes[4];
    uint8_t netBytes[4];

    if (inet_pton(AF_INET, address.toString().c_str(), addrBytes) != 1) {
        return false;
    }
    if (inet_pton(AF_INET, network.toString().c_str(), netBytes) != 1) {
        return false;
    }

    for (uint32_t i = 0; i < 4; ++i) {
        if (maskBits >= 8) {
            if (addrBytes[i] != netBytes[i]) {
                return false;
            }
            maskBits -= 8;
        } else if (maskBits > 0) {
            uint8_t mask = static_cast<uint8_t>(0xFF << (8 - maskBits));
            if ((addrBytes[i] & mask) != (netBytes[i] & mask)) {
                return false;
            }
            maskBits = 0;
        } else {
            break;
        }
    }
    return true;
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
      network_from(std::move(from_ip)),
      network_from_mask(from_mask),
      network_to(std::move(to_ip)),
      network_to_mask(to_mask)
{
}

bool DecryptionProfile::loadCryptoMaterial()
{
    if (ca_certificate_path.empty() || ca_private_key_path.empty()) {
        std::cout << "[DecryptionProfile] Missing CA certificate or key path." << std::endl;
        return false;
    }

    FILE* certFile = fopen(ca_certificate_path.c_str(), "r");
    if (!certFile) {
        std::cout << "[DecryptionProfile] Failed to open CA certificate: "
                  << ca_certificate_path << std::endl;
        return false;
    }
    ca_cert = PEM_read_X509(certFile, nullptr, nullptr, nullptr);
    fclose(certFile);

    FILE* keyFile = fopen(ca_private_key_path.c_str(), "r");
    if (!keyFile) {
        std::cout << "[DecryptionProfile] Failed to open CA private key: "
                  << ca_private_key_path << std::endl;
        return false;
    }
    ca_private_key = PEM_read_PrivateKey(keyFile, nullptr, nullptr, nullptr);
    fclose(keyFile);

    if (!ca_cert || !ca_private_key) {
        std::cout << "[DecryptionProfile] Failed to load CA materials." << std::endl;
        return false;
    }

    std::cout << "[DecryptionProfile] Loaded CA materials from "
              << ca_certificate_path << " and " << ca_private_key_path << std::endl;
    return true;
}

bool DecryptionProfile::shouldDecrypt() const
{
    return should_decrypt;
}

bool DecryptionProfile::doesMatchProfile(Session const& session) const
{
    const auto& forward = session.getSourceToDestinationFlow();
    const auto& reverse = session.getDestinationToSourceFlow();

    if (matchesEndpoints(forward.internal_ip, forward.external_ip)) {
        return true;
    }
    return matchesEndpoints(reverse.internal_ip, reverse.external_ip);
}

bool DecryptionProfile::matchesEndpoints(const pcpp::IPv4Address& source, const pcpp::IPv4Address& destination) const
{
    return matchesNetwork(source, network_from, network_from_mask) &&
           matchesNetwork(destination, network_to, network_to_mask);
}

X509* DecryptionProfile::getCaCert() const
{
    return ca_cert;
}

EVP_PKEY* DecryptionProfile::getCaPrivateKey() const
{
    return ca_private_key;
}

uint8_t* DecryptionProfile::decrypt()
{
    return nullptr;
}
