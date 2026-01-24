#ifndef BASIC_FIREWALL_NATSERVICE_H
#define BASIC_FIREWALL_NATSERVICE_H
#include <pcapplusplus/IPv4Layer.h>

#include "../session/sessions/NatSession.h"
#include "../session/sessions/Session.h"

/**
 * @brief NAT transformation helper.
 */
class NatService {
public:
    /**
     * @brief Apply NAT translation to a packet using a session.
     *
     * @param session NAT session data.
     * @param ipLayerPacket IPv4 packet to modify.
     * @return Pointer to the translated IPv4 layer.
     */
    pcpp::IPv4Layer* applyNat(NatSession session, pcpp::IPv4Layer* ipLayerPacket);
};

#endif
