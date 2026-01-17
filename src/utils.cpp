#include "pcapplusplus/PcapLiveDeviceList.h"
#include "pcapplusplus/PcapLiveDevice.h"
#include "pcapplusplus/IPv4Layer.h"
#include "pcapplusplus/TcpLayer.h"
#include "../include/configuration/Config.h"
#include "../include/session/sessions/Session.h"
#include "../include/session/sessions/DecryptionSession.h"
#include "../include/session/sessions/NatSession.h"
#include "utils.h"
#include <arpa/inet.h>

using namespace pcpp;

SessionFlowKey getSessionFlowKey(
    const IPv4Layer* ipLayerPacket,
    const TcpLayer* tcpLayerPacket
)
{
    return Session::generateSessionFlowKey(
        ipLayerPacket->getSrcIPv4Address(),
        ntohs(tcpLayerPacket->getTcpHeader()->portSrc),
        ipLayerPacket->getDstIPv4Address(),
        ntohs(tcpLayerPacket->getTcpHeader()->portDst)
    );
}

Session* createOrGetSession(
    SessionTable &sessionTable,
    const SessionFlowKey& key,
    const IPv4Layer* ipLayerPacket,
    const TcpLayer* tcpLayerPacket,
    PcapLiveDevice* captureInterface
)
{
    if (Session* existing = sessionTable.findSession(key)) {
        return existing;
    }
    Session session(
        captureInterface->getIPv4Address(),
        captureInterface->getIPv4Address(),
        ipLayerPacket->getSrcIPv4Address(),
        ntohs(tcpLayerPacket->getTcpHeader()->portSrc),
        ipLayerPacket->getDstIPv4Address(),
        ntohs(tcpLayerPacket->getTcpHeader()->portDst)
    );
    return &sessionTable.createSession(key, std::move(session));
}

DecryptionSession createOrGetDecryptionSession(
    DecryptionSessionTable &decryptionSessionTable,
    const SessionFlowKey& key,
    Session* session,
    DecryptionProfile
)
{
    if (auto* existing = decryptionSessionTable.findSession(key)) {
        return *static_cast<DecryptionSession*>(existing);
    }
    DecryptionSession new_session(
        session->getSourceToDestinationFlow().internal_ip,
        session->getSourceToDestinationFlow().internal_ip,
        session->getSourceToDestinationFlow().internal_port,
        session->getSourceToDestinationFlow().external_ip,
        session->getSourceToDestinationFlow().external_port
    );
    return static_cast<DecryptionSession&>(decryptionSessionTable.createSession(key, std::move(new_session)));
}

NatSession createOrGetNatSession(
    NatSessionTable &natSessionTable,
    const SessionFlowKey& key,
    Session* session,
    const IPv4Layer* ipLayerPacket,
    const TcpLayer* tcpLayerPacket,
    const NatPolicy& nat_policy
)
{
    if (auto* existing = natSessionTable.findSession(key)) {
        return *static_cast<NatSession*>(existing);
    }
    if (ipLayerPacket && tcpLayerPacket) {
        uint16_t src_port = ntohs(tcpLayerPacket->getTcpHeader()->portSrc);
        uint16_t dst_port = ntohs(tcpLayerPacket->getTcpHeader()->portDst);
        if (auto* existing = natSessionTable.findByNatMapping(
            ipLayerPacket->getDstIPv4Address(),
            dst_port,
            ipLayerPacket->getSrcIPv4Address(),
            src_port
        )) {
            return *existing;
        }
    }

    const auto& flow = session->getSourceToDestinationFlow();
    pcpp::IPv4Address nat_ip = nat_policy.getTranslatedSourceIp();
    uint16_t nat_port = flow.internal_port;
    if (nat_policy.isSourceNat()) {
        nat_port = NatPolicy::acquirePort().value_or(flow.internal_port);
    }
    NatSession new_session(
        flow.internal_ip,
        flow.internal_port,
        flow.external_ip,
        flow.external_port,
        nat_ip,
        nat_port,
        nat_policy.isSourceNat(),
        nat_policy.isDestinationNat()
    );
    auto& stored = natSessionTable.createSession(key, new_session);
    if (nat_policy.isSourceNat()) {
        SessionFlowKey reverse_key{
            flow.external_ip,
            flow.external_port,
            nat_ip,
            nat_port,
            key.protocol
        };
        NatSession reverse_session = new_session;
        natSessionTable.createSession(reverse_key, std::move(reverse_session));
    }
    return static_cast<NatSession&>(stored);
}

bool isNotEncryptedSession(Session*)
{
    return true;
}
