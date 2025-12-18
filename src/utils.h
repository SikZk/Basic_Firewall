//
// Created by mikolaj on 11/29/25.
//

#ifndef BASIC_FIREWALL_UTILS_H
#define BASIC_FIREWALL_UTILS_H

#include <vector>
#include "pcapplusplus/PcapLiveDeviceList.h"
#include "pcapplusplus/PcapLiveDevice.h"
#include "pcapplusplus/IPv4Layer.h"
#include "../include/configuration/Config.h"
#include "../include/session/session_tables/DecryptionSessionTable.h"
using namespace pcpp;


template <typename C, typename T>
T matchBasedOnObject(
    C* c,
    std::vector<T>& data_to_match_object_to
);

SessionFlowKey getSessionFlowKey(
    const IPv4Layer* ipLayerPacket,
    const TcpLayer* tcpLayerPacket
);
Session* createOrGetSession(
    SessionTable &sessionTable,
    const SessionFlowKey& key,
    const IPv4Layer* ipLayerPacket,
    const TcpLayer* tcpLayerPacket,
    PcapLiveDevice* captureInterface
);
DecryptionSession createOrGetDecryptionSession(
   DecryptionSessionTable &decryptionSessionTable,
   const SessionFlowKey& key,
   Session* session,
   DecryptionProfile decryption_profile
);
NatSession createOrGetNatSession(
   NatSessionTable &decryptionSessionTable,
   const SessionFlowKey& key,
   Session* session,
   NatPolicy nat_policy
);
bool isNotEncryptedSession(Session *session);

#endif
