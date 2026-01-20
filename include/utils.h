#ifndef BASIC_FIREWALL_INCLUDE_UTILS_H
#define BASIC_FIREWALL_INCLUDE_UTILS_H

#include "pcapplusplus/PcapLiveDeviceList.h"
#include "pcapplusplus/PcapLiveDevice.h"
#include "pcapplusplus/IPv4Layer.h"
#include "pcapplusplus/TcpLayer.h"
#include <type_traits>
#include <vector>

// Dependencies
#include "configuration/Config.h"
#include "session/session_tables/DecryptionSessionTable.h"
#include "routing/RoutingEngine.h"
#include "policies/NatService.h"
#include "session/sessions/Session.h" 

using namespace pcpp;

template <typename C, typename T>
T matchBasedOnObject(
    C* c,
    std::vector<T>& data_to_match_object_to
)
{
    for (auto& candidate : data_to_match_object_to) {
        if constexpr (std::is_same_v<C, IPv4Layer> && std::is_same_v<T, SecurityPolicy>) {
            if (candidate.does_match_policy(*c)) {
                return candidate;
            }
        } else if constexpr (std::is_same_v<C, Session> && std::is_same_v<T, DecryptionProfile>) {
            if (candidate.doesMatchProfile(*c)) {
                return candidate;
            }
        } else if constexpr (std::is_same_v<C, Session> && std::is_same_v<T, NatPolicy>) {
            return candidate;
        }
    }

    if (!data_to_match_object_to.empty()) {
        return data_to_match_object_to.front();
    }

    if constexpr (std::is_same_v<T, SecurityPolicy>) {
        return SecurityPolicy("0.0.0.0", 0, "0.0.0.0", 0, 0, 0, SecurityPolicy::Action::Allow, {});
    } else if constexpr (std::is_same_v<T, DecryptionProfile>) {
        return DecryptionProfile("default", "", "", "0.0.0.0", 0, "0.0.0.0", 0);
    } else if constexpr (std::is_same_v<T, NatPolicy>) {
        return NatPolicy("0.0.0.0", 0, "0.0.0.0", 0, 0, 0);
    } else {
        return T{};
    }
}

SessionFlowKey getSessionFlowKey(
    const IPv4Layer* ipLayerPacket,
    const TcpLayer* tcpLayerPacket
);

// Moved helper functions
SessionFlowKey getKeyFromPacket(Packet& packet);
bool isInternalNetwork(const IPv4Address& ip);
bool isHttpsPacket(const TcpLayer* tcpLayer);

void sendTcpRst(
    Packet& blockedPacket, 
    PcapLiveDevice* inDev, 
    RoutingEngine& routingEngine, 
    NatService& natService,
    const RoutingTable& routingTable
);

Session* createOrGetSession(
    SessionTable &sessionTable,
    const SessionFlowKey& key,
    const IPv4Layer* ipLayerPacket,
    const TcpLayer* tcpLayerPacket,
    PcapLiveDevice* captureInterface
);
DecryptionSession* createOrGetDecryptionSession(
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
