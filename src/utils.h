//
// Created by mikolaj on 11/29/25.
//

#ifndef BASIC_FIREWALL_UTILS_H
#define BASIC_FIREWALL_UTILS_H
#include "pcapplusplus/PcapLiveDeviceList.h"
#include "pcapplusplus/PcapLiveDevice.h"
#include "pcapplusplus/IPv4Layer.h"
#include "../include/configuration/Config.h"
#include "../include/session/session_tables/DecryptionSessionTable.h"
using namespace pcpp;

SecurityPolicy match_security_policy(pcpp::IPv4Layer& ipLayerPacket, std::vector<SecurityPolicy>& security_profiles);

Session createOrGetSession(
    SessionTable &sessionTable,
    const SessionFlowKey& key,
    const IPv4Layer* ipLayerPacket,
    const TcpLayer* tcpLayerPacket,
    PcapLiveDevice* captureInterface
);

DecryptionProfile matchDecryptionProfile(
    Session session, std::vector<DecryptionProfile>& decryption_profiles
);
NatPolicy matchNatPolicy(
    Session session, std::vector<NatPolicy>& nat_policy
);

DecryptionSession createOrGetDecryptionSession(
   DecryptionSessionTable &decryptionSessionTable,
   const SessionFlowKey& key,
   Session session,
   DecryptionProfile decryption_profile
);
NatSession createOrGetNatSession(
   NatSessionTable &decryptionSessionTable,
   const SessionFlowKey& key,
   Session session,
   NatPolicy nat_policy
);


#endif