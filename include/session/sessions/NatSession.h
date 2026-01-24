#ifndef BASIC_FIREWALL_NATSESSION_H
#define BASIC_FIREWALL_NATSESSION_H
#include <cstdint>
#include <pcapplusplus/IpAddress.h>

#include "Session.h"

/**
 * @brief Session that tracks NAT translation state.
 */
class NatSession : public Session {
public:
    /**
     * @brief Construct a NAT session.
     *
     * @param firewall_interface_ip Firewall interface IP.
     * @param source_ip Original source IP.
     * @param source_port Original source port.
     * @param destination_ip Original destination IP.
     * @param destination_port Original destination port.
     * @param nat_ip Translated NAT IP.
     * @param nat_port Translated NAT port.
     * @param is_source_nat True if source NAT is applied.
     */
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
    /**
     * @brief Destroy the NAT session.
     */
    ~NatSession() = default;
};

#endif
