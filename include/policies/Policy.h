//
// Created by mikolaj on 11/5/25.
//

#ifndef BASIC_FIREWALL_POLICY_H
#define BASIC_FIREWALL_POLICY_H
#include <pcapplusplus/IpAddress.h>

class Policy {

  private:
    pcpp::IPv4Address source_ip;
    pcpp::IPv4Address destination_ip;
    std::uint16_t     source_port{0};
    std::uint16_t     destination_port{0};

  public:
    bool match_policy(pcpp::IPv4Layer ipv4_packet);


};

#endif //BASIC_FIREWALL_POLICY_H