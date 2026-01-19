#include "../../../include/session/sessions/NatSession.h"
#include <iostream> // For debug if needed

NatSession::NatSession(
    pcpp::IPv4Address firewall_interface_ip,
    pcpp::IPv4Address source_ip,
    uint16_t source_port,
    pcpp::IPv4Address destination_ip,
    uint16_t destination_port,
    pcpp::IPv4Address nat_ip,
    uint16_t nat_port,
    bool is_source_nat
)
    : Session(
        firewall_interface_ip,
        firewall_interface_ip,
        source_ip,
        source_port,
        destination_ip,
        destination_port
    )
{
    (void)is_source_nat;

    // --- CRITICAL FIX ---
    // Klasa bazowa Session ustawia 'destination_to_source' jako idealne lustro (Dst -> Src).
    // W NAT to nieprawda. Ruch powrotny idzie z Internetu (Dst) do Firewalla (NAT IP).
    // Nadpisujemy parametry 'external' w przepływie powrotnym, aby przechowywały adres NAT.

    // destination_to_source:
    // internal_ip/port = Remote Server (1.1.1.1)
    // external_ip/port = Client (10.x.x.x) <--- TO ZMIENIAMY na NAT IP (192.168.1.29)

    this->destination_to_source.external_ip = nat_ip;
    this->destination_to_source.external_port = nat_port;
}