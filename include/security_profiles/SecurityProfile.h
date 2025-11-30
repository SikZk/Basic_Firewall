//
// Created by mikolaj on 11/23/25.
//

#ifndef BASIC_FIREWALL_SECURITYPROFILE_H
#define BASIC_FIREWALL_SECURITYPROFILE_H
#include <string>

#include "../session/sessions/DecryptionSession.h"
#include "../session/sessions/Session.h"
enum Action {
    ALLOW,
    BLOCK,
    ALERT
};

class SecurityProfile {
    public:
    virtual ~SecurityProfile() = default;

    SecurityProfile();


    virtual Action scan(const DecryptionSession&, pcpp::IPv4Layer ipv4_packet) = 0;
};

#endif