//
// Created by mikolaj on 11/5/25.
//

#ifndef BASIC_FIREWALL_DECRYPTION_PROFILE_H
#define BASIC_FIREWALL_DECRYPTION_PROFILE_H


#include <string>
#include <pcapplusplus/IpAddress.h>
#include <openssl/evp.h>
#include <openssl/x509.h>
#include "../session/sessions/Session.h"


class DecryptionProfile {
    public:
        bool should_decrypt;
        std::string profile_name;
        std::string ca_certificate_path;
        std::string ca_private_key_path;
        X509* ca_cert = nullptr;       // ca
        EVP_PKEY* ca_private_key = nullptr; //private key
        DecryptionProfile(std::string name,
                          std::string ca_cert, std::string ca_key,
                          std::string from_ip, uint32_t from_mask,
                          std::string to_ip, uint32_t to_mask);

        bool loadCryptoMaterial();
        bool shouldDecrypt() const;
        bool doesMatchProfile(Session const& session) const;
        bool matchesEndpoints(const pcpp::IPv4Address& source, const pcpp::IPv4Address& destination) const;
        uint8_t* decrypt();
    private:
        pcpp::IPv4Address network_from;
        uint32_t network_from_mask;
        pcpp::IPv4Address network_to;
        uint32_t network_to_mask;
   };


#endif
