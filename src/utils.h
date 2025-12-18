//
// Created by mikolaj on 11/29/25.
//

#ifndef BASIC_FIREWALL_UTILS_H
#define BASIC_FIREWALL_UTILS_H

#include <vector>
#include <stdexcept>
#include <type_traits>
#include "pcapplusplus/PcapLiveDeviceList.h"
#include "pcapplusplus/PcapLiveDevice.h"
#include "pcapplusplus/IPv4Layer.h"
#include "../include/configuration/Config.h"
#include "../include/session/session_tables/DecryptionSessionTable.h"
using namespace pcpp;

template <typename C, typename T>
inline T matchBasedOnObject(C* c, std::vector<T>& data_to_match_object_to) {
    for (auto& element : data_to_match_object_to) {
        if constexpr (requires { element.doesMatchProfile(*c); }) {
            if (element.doesMatchProfile(*c)) {
                return element;
            }
        } else if constexpr (requires { element.does_match_policy(*c); }) {
            if (element.does_match_policy(*c)) {
                return element;
            }
        }
    }
    if (data_to_match_object_to.empty()) {
        throw std::runtime_error("No elements to match");
    }
    return data_to_match_object_to.front();
}

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
