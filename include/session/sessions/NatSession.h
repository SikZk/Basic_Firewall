//
// Created by mikolaj on 11/26/25.
//

#ifndef BASIC_FIREWALL_NATSESSION_H
#define BASIC_FIREWALL_NATSESSION_H
#include <cstdint>
#include <pcapplusplus/IpAddress.h>

#include "Session.h"


class NatSession : public Session {
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
    pcpp::IPv4Address getInternalIp() const;
    uint16_t getInternalPort() const;
    pcpp::IPv4Address getExternalIp() const;
    uint16_t getExternalPort() const;
    pcpp::IPv4Address getNatIp() const;
    uint16_t getNatPort() const;
    bool isSourceNat() const;

private:
    pcpp::IPv4Address internal_ip_;
    uint16_t internal_port_{0};
    pcpp::IPv4Address external_ip_;
    uint16_t external_port_{0};
    pcpp::IPv4Address nat_ip_;
    uint16_t nat_port_{0};
    bool is_source_nat_{true};
};

#endif //BASIC_FIREWALL_NATSESSION_H
