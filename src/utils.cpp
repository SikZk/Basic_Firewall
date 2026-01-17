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
    NatPolicy
)
{
    if (auto* existing = natSessionTable.findSession(key)) {
        return *static_cast<NatSession*>(existing);
    }
    NatSession new_session(
        session->getSourceToDestinationFlow().internal_ip,
        session->getSourceToDestinationFlow().internal_ip,
        session->getSourceToDestinationFlow().internal_port,
        session->getSourceToDestinationFlow().external_ip,
        session->getSourceToDestinationFlow().external_port,
        session->getSourceToDestinationFlow().external_ip,
        session->getSourceToDestinationFlow().external_port,
        true
    );
    return static_cast<NatSession&>(natSessionTable.createSession(key, std::move(new_session)));
}

bool isNotEncryptedSession(Session*)
{
    return true;
}
