#include "pcapplusplus/PcapLiveDeviceList.h"
#include "pcapplusplus/PcapLiveDevice.h"
#include "pcapplusplus/IPv4Layer.h"
#include "pcapplusplus/TcpLayer.h"
#include "../include/configuration/Config.h"
#include "../include/session/sessions/Session.h"
#include "../include/session/sessions/DecryptionSession.h"
#include "../include/session/sessions/NatSession.h"
#include "../include/session/session_tables/SessionTable.h"
#include "../include/session/session_tables/DecryptionSessionTable.h"
#include "../include/session/session_tables/NatSessionTable.h"
#include "../include/policies/NatPolicy.h"
using namespace pcpp;

SessionFlowKey getSessionFlowKey(
    const IPv4Layer* ipLayerPacket,
    const TcpLayer* tcpLayerPacket
) {
    IPv4Address src_ip = ipLayerPacket->getSrcIPv4Address();
    IPv4Address dst_ip = ipLayerPacket->getDstIPv4Address();
    uint16_t src_port = tcpLayerPacket ? tcpLayerPacket->getSrcPort() : 0;
    uint16_t dst_port = tcpLayerPacket ? tcpLayerPacket->getDstPort() : 0;
    return Session::generateSessionFlowKey(src_ip, src_port, dst_ip, dst_port);
}

Session* createOrGetSession(
    SessionTable &sessionTable,
    const SessionFlowKey& key,
    const IPv4Layer* ipLayerPacket,
    const TcpLayer* tcpLayerPacket,
    PcapLiveDevice* /*captureInterface*/
) {
    if (auto* existing = sessionTable.findSession(key)) {
        return existing;
    }
    Session session(
        ipLayerPacket->getSrcIPv4Address(),
        ipLayerPacket->getDstIPv4Address(),
        ipLayerPacket->getSrcIPv4Address(),
        tcpLayerPacket ? tcpLayerPacket->getSrcPort() : 0,
        ipLayerPacket->getDstIPv4Address(),
        tcpLayerPacket ? tcpLayerPacket->getDstPort() : 0
    );
    return &sessionTable.createSession(key, std::move(session));
}

DecryptionSession createOrGetDecryptionSession(
   DecryptionSessionTable &decryptionSessionTable,
   const SessionFlowKey& key,
   Session* session,
   DecryptionProfile /*decryption_profile*/
) {
    if (auto* existing = decryptionSessionTable.findSession(key)) {
        return *static_cast<DecryptionSession*>(existing);
    }
    DecryptionSession dec_session(key.src_ip, key.src_ip, key.src_port, key.dst_ip, key.dst_port);
    decryptionSessionTable.createSession(key, dec_session);
    return dec_session;
}

NatSession createOrGetNatSession(
   NatSessionTable &natSessionTable,
   const SessionFlowKey& key,
   Session* session,
   NatPolicy /*nat_policy*/
) {
    if (auto* existing = natSessionTable.findSession(key)) {
        return *static_cast<NatSession*>(existing);
    }
    NatSession nat_session(key.src_ip, key.src_ip, key.src_port, key.dst_ip, key.dst_port, key.dst_ip, key.dst_port, true);
    natSessionTable.createSession(key, nat_session);
    return nat_session;
}

bool isNotEncryptedSession(Session *session) {
    return session == nullptr || session->getDataLength() == 0;
}
