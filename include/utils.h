#ifndef BASIC_FIREWALL_INCLUDE_UTILS_H
#define BASIC_FIREWALL_INCLUDE_UTILS_H

#include "pcapplusplus/PcapLiveDevice.h"
#include "pcapplusplus/IPv4Layer.h"
#include "pcapplusplus/TcpLayer.h"
#include <type_traits>
#include <vector>

#include "configuration/Config.h"
#include "session/session_tables/DecryptionSessionTable.h"
#include "routing/RoutingEngine.h"
#include "policies/NatService.h"
#include "session/sessions/Session.h" 

using namespace pcpp;

/**
 * @brief Match an object to the first applicable policy/profile.
 *
 * @tparam C Type of the object to match (IPv4Layer, Session, etc).
 * @tparam T Type of the candidate entries (SecurityPolicy, DecryptionProfile, NatPolicy).
 * @param c Pointer to the object to match.
 * @param data_to_match_object_to Candidate entries for matching.
 * @return First matching entry or a default entry.
 */
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

/**
 * @brief Build a session key from IP and TCP layers.
 *
 * @param ipLayerPacket IPv4 layer pointer.
 * @param tcpLayerPacket TCP layer pointer.
 * @return Session flow key for the packet.
 */
SessionFlowKey getSessionFlowKey(
    const IPv4Layer* ipLayerPacket,
    const TcpLayer* tcpLayerPacket
);

/**
 * @brief Extract a session key from a packet.
 *
 * @param packet Packet to inspect.
 * @return Session flow key for the packet.
 */
SessionFlowKey getKeyFromPacket(Packet& packet);
/**
 * @brief Check whether an IP address is internal.
 *
 * @param ip IPv4 address to check.
 * @return True when the address is in the internal range.
 */
bool isInternalNetwork(const IPv4Address& ip);
/**
 * @brief Determine if a TCP packet appears to carry HTTPS traffic.
 *
 * @param tcpLayer TCP layer pointer.
 * @return True if the packet is likely HTTPS.
 */
bool isHttpsPacket(const TcpLayer* tcpLayer);

/**
 * @brief Send a TCP reset for a blocked packet.
 *
 * @param blockedPacket Packet to reset.
 * @param inDev Input device where packet was captured.
 * @param routingEngine Routing engine for forwarding.
 * @param natService NAT service for address translation.
 * @param routingTable Routing table used for forwarding.
 */
void sendTcpRst(
    Packet& blockedPacket, 
    PcapLiveDevice* inDev, 
    RoutingEngine& routingEngine, 
    NatService& natService,
    const RoutingTable& routingTable
);

/**
 * @brief Get an existing session or create a new one.
 *
 * @param sessionTable Table containing sessions.
 * @param key Session flow key.
 * @param ipLayerPacket IPv4 layer pointer.
 * @param tcpLayerPacket TCP layer pointer.
 * @param captureInterface Interface that captured the packet.
 * @return Pointer to the existing or newly created session.
 */
Session* createOrGetSession(
    SessionTable &sessionTable,
    const SessionFlowKey& key,
    const IPv4Layer* ipLayerPacket,
    const TcpLayer* tcpLayerPacket,
    PcapLiveDevice* captureInterface
);
/**
 * @brief Get an existing decryption session or create a new one.
 *
 * @param decryptionSessionTable Table containing decryption sessions.
 * @param key Session flow key.
 * @param session Base session associated with the flow.
 * @param decryption_profile Decryption profile to apply.
 * @return Pointer to the existing or newly created decryption session.
 */
DecryptionSession* createOrGetDecryptionSession(
   DecryptionSessionTable &decryptionSessionTable,
   const SessionFlowKey& key,
   Session* session,
   DecryptionProfile decryption_profile
);
/**
 * @brief Get an existing NAT session or create a new one.
 *
 * @param decryptionSessionTable Table containing NAT sessions.
 * @param key Session flow key.
 * @param session Base session associated with the flow.
 * @param nat_policy NAT policy to apply.
 * @return NAT session object.
 */
NatSession createOrGetNatSession(
   NatSessionTable &decryptionSessionTable,
   const SessionFlowKey& key,
   Session* session,
   NatPolicy nat_policy
);
/**
 * @brief Determine whether a session should skip decryption.
 *
 * @param session Session pointer.
 * @return True when the session is not encrypted.
 */
bool isNotEncryptedSession(Session *session);

#endif
