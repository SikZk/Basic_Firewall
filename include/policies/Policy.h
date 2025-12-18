//
// Created by mikolaj on 11/5/25.
//

#ifndef BASIC_FIREWALL_POLICY_H
#define BASIC_FIREWALL_POLICY_H
#include <cstdint>
#include <string>
#include <memory_resource>
#include <pcapplusplus/IpAddress.h>

class Policy {

  private:
      pcpp::IPv4Network network_from;
      pcpp::IPv4Network network_to;
      pcpp::IPv4Address network_from_base;
      pcpp::IPv4Address network_to_base;
      std::uint8_t      network_from_prefix{0};
      std::uint8_t      network_to_prefix{0};
      std::uint16_t     source_port{0};
      std::uint16_t     destination_port{0};

  public:
    Policy(
            std::pmr::string network_from_str,
            uint32_t         from_mask,
            std::pmr::string network_to_str,
            uint32_t         to_mask,
            std::uint16_t    src_port,
            std::uint16_t    dest_port
        )
        : network_from(std::string(network_from_str) + "/" + std::to_string(from_mask)),
        network_to  (std::string(network_to_str)   + "/" + std::to_string(to_mask)),
        network_from_base(std::string(network_from_str)),
        network_to_base(std::string(network_to_str)),
        network_from_prefix(static_cast<std::uint8_t>(from_mask)),
        network_to_prefix(static_cast<std::uint8_t>(to_mask)),
        source_port(std::move(src_port)), destination_port(std::move(dest_port)) { };

    // Metoda sprawdzająca czy dany pakiet pasuje do polityki
    bool does_match_policy(pcpp::IPv4Layer ipv4_packet);


};

#endif
