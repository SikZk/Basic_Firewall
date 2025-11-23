//
// Created by mikolaj on 11/23/25.
//

#ifndef BASIC_FIREWALL_DECRYPTIONSESSION_H
#define BASIC_FIREWALL_DECRYPTIONSESSION_H
#include "Session.h"

class DecryptionSession {
public:
    uint64_t session_id;
    SessionState state;
    bool is_ssl;

    DecryptionConnectionLeg client_side; // Połączenie z hostem w sieci LAN
    DecryptionConnectionLeg server_side; // Połączenie z Internetem

    Session(uint64_t id, uint32_t srcIP, uint16_t srcPort, uint32_t dstIP, uint16_t dstPort);
    ~Session();

    // Metoda do sprawdzenia, czy pakiet należy do tej sesji
    bool match(pcpp::Packet& packet);
};

#endif //BASIC_FIREWALL_DECRYPTIONSESSION_H