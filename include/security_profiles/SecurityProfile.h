//
// Created by mikolaj on 11/23/25.
//

#ifndef BASIC_FIREWALL_SECURITYPROFILE_H
#define BASIC_FIREWALL_SECURITYPROFILE_H
#include <string>
#include <pcapplusplus/IPv4Layer.h>

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

    virtual Action scan(Session* session, const pcpp::Packet& packet) = 0;
    virtual Action scan(const DecryptionSession&, const pcpp::Packet& packet) = 0;
};

#endif
