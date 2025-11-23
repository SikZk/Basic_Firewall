//
// Created by mikolaj on 11/5/25.
//

#ifndef BASIC_FIREWALL_DECRYPTION_PROFILE_H
#define BASIC_FIREWALL_DECRYPTION_PROFILE_H
#include "../session/session.h"
#include <vector>
#include <string>


class DecryptionProfile {
    public:
        std::string profile_name;
        std::string ca_certificate_path;
        std::string ca_private_key_path;
        X509* ca_cert = nullptr;       // ca
        EVP_PKEY* ca_private_key = nullptr; //private key
        DecryptionProfile(std::string name,
                          std::string ca_cert, std::string ca_key,
                          std::string from_ip, uint32_t from_mask,
                          std::string to_ip, uint32_t to_mask);

        ~DecryptionProfile() = default;

        bool loadCryptoMaterial();
        bool shouldDecrypt(const pcpp::Packet& packet);

    private:
        pcpp::IPv4Network network_from;
        pcpp::IPv4Network network_to;
   };


#endif //BASIC_FIREWALL_DECRYPTION_PROFILE_H