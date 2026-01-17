//
// Created by mikolaj on 11/30/25.
//

#ifndef BASIC_FIREWALL_NATSERVICE_H
#define BASIC_FIREWALL_NATSERVICE_H
#include <pcapplusplus/IPv4Layer.h>

#include "../session/sessions/NatSession.h"
#include "../session/sessions/Session.h"

class NatService {

    public:
        pcpp::IPv4Layer* applyNat(const NatSession& session, pcpp::IPv4Layer* ipLayerPacket);
};


#endif //BASIC_FIREWALL_NATSERVICE_H
