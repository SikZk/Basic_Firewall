//
// Created by mikolaj on 11/26/25.
//

#ifndef BASIC_FIREWALL_NATSESSION_H
#define BASIC_FIREWALL_NATSESSION_H
#include <cstdint>
#include <pcapplusplus/IpAddress.h>

#include "Session.h"


class NatSession : public Session {
private:
    pcpp::IPv4Address nat_ip;
    uint16_t nat_port;
    bool is_source_nat;

public:
    NatSession(
        pcpp::IPv4Address firewall_interface_ip,
        pcpp::IPv4Address source_ip,
        uint16_t          source_port,
        pcpp::IPv4Address destination_ip,
        uint16_t          destination_port,
        pcpp::IPv4Address nat_ip,
        uint16_t nat_port,
        bool is_source_nat
    );
    ~NatSession() = default;
    const pcpp::IPv4Address& getNatIp() const;
    uint16_t getNatPort() const;
    bool isSourceNat() const;
};

#endif //BASIC_FIREWALL_NATSESSION_H
