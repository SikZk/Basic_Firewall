#include "pcapplusplus/PcapLiveDeviceList.h"
#include "pcapplusplus/PcapLiveDevice.h"
#include "pcapplusplus/IPv4Layer.h"
#include "../include/configuration/Config.h"
#include "../include/session/sessions/Session.h"
using namespace pcpp;

SecurityPolicy match_security_policy(const IPv4Layer&  ipLayerPacket, const std::vector<SecurityPolicy>& security_profiles) {
    for (SecurityPolicy security_policy: security_profiles) {
        if (security_policy.does_match_policy(ipLayerPacket)) {
            return security_policy;
        }
    };
    throw std::runtime_error("No matching security policy found");
}

Session createOrGetSession(
    SessionTable &sessionTable,
    const SessionFlowKey& key,
    const IPv4Layer* ipLayerPacket,
    const TcpLayer* tcpLayerPacket,
    PcapLiveDevice* captureInterface
) {

    if (!sessionTable.doesSessionExist(key)) {
        const Session session(
            captureInterface->getIPv4Address(),
            captureInterface->getIPv4Address(),
            ipLayerPacket->getSrcIPAddress().getIPv4(),
            tcpLayerPacket->getSrcPort(),
            ipLayerPacket->getDstIPAddress().getIPv4(),
            tcpLayerPacket->getDstPort()
        );
        sessionTable.createSession(key, session);
        return session;
    }
    Session session = *sessionTable.findSession(key);
    session.appendData(ipLayerPacket->getData(), ipLayerPacket->getDataLen());
    return session;
}


DecryptionProfile matchDecryptionProfile(
    Session session, std::vector<DecryptionProfile>& decryption_profiles
) {
    for (DecryptionProfile decryption_profile: decryption_profiles) {
        if (decryption_profile.doesMatchProfile(session)) {
            return decryption_profile;
        }
    };
    throw std::runtime_error("No matching decryption profile found");

};