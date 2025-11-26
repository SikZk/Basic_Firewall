//
// Created by mikolaj on 11/26/25.
//

#ifndef BASIC_FIREWALL_DECRYPTIONSESSION_H
#define BASIC_FIREWALL_DECRYPTIONSESSION_H
#include <cstdint>
#include <openssl/types.h>
#include <pcapplusplus/IpAddress.h>
#include "Session.h"

class DecryptionSession : public Session {
private:
    uint32_t seq_num;
    uint32_t ack_num;
    SSL* ssl_handle = nullptr;
    BIO* read_bio = nullptr;
    BIO* write_bio = nullptr;
public:
    DecryptionSession(
        pcpp::IPv4Address firewall_interface_ip,
        pcpp::IPv4Address source_ip,
        uint16_t          source_port,
        pcpp::IPv4Address destination_ip,
        uint16_t          destination_port
    );
    ~DecryptionSession() = default;
};

#endif //BASIC_FIREWALL_DECRYPTIONSESSION_H