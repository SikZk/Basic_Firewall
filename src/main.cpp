// main.cpp
#include "pcapplusplus/PcapLiveDeviceList.h"
#include "pcapplusplus/PcapLiveDevice.h"
#include "pcapplusplus/RawPacket.h"
#include "pcapplusplus/Packet.h"
#include "pcapplusplus/IPv4Layer.h"

#include <cstdio>
#include <cctype>
#include <csignal>
#include <thread>
#include <chrono>
#include "../include/configuration/Config.h"
#include "./utils.h"
#include "../include/session/session_tables/DecryptionSessionTable.h"
#include "../include/decryption/DecryptionManager.h"

using namespace pcpp;

static PcapLiveDevice* captureInterface = nullptr;
static Config configuration("../resources/config.json");
static volatile std::sig_atomic_t stopSignal = 0;
static SessionTable sessionTable;
static DecryptionSessionTable decryptionSessionTable;
DecryptionManager decryptionManager;
static NatSessionTable natSessionTable;



static void exitProgram(int) {
    stopSignal = 1;
    if (captureInterface && captureInterface->isOpened()) {
        captureInterface->stopCapture();
    }
}


static void onPacketArrives(RawPacket* rawPacket, PcapLiveDevice*, void*) {

    Packet parsedPacket(rawPacket);
    if (!parsedPacket.isPacketOfType(IPv4)) {
        return;
    }
    IPv4Layer* ipLayerPacket = parsedPacket.getLayerOfType<IPv4Layer>();
    TcpLayer* tcpLayerPacket = parsedPacket.getLayerOfType<TcpLayer>();

    SecurityPolicy security_policy = match_security_policy(
        *ipLayerPacket,
        configuration.security_policies
    );
    if (!security_policy.is_allow_packet()) {
        return;
    }

    std::vector<SecurityProfile> security_profiles_to_apply =
        security_policy.evaluate_security_profiles(*ipLayerPacket);

    SessionFlowKey key{
        ipLayerPacket->getSrcIPAddress().getIPv4(),
        tcpLayerPacket->getSrcPort(),
        ipLayerPacket->getDstIPAddress().getIPv4(),
        tcpLayerPacket->getDstPort(),
        ipLayerPacket->getProtocol()
    };
    //TODO improve the way of creating sessions and matching policies from configuration, this could be wrapped into some generic function
    Session session = createOrGetSession(
        sessionTable,
        key,
        ipLayerPacket,
        tcpLayerPacket,
        captureInterface
    );
    //TODO improve the way of creating sessions and matching policies from configuration, this could be wrapped into some generic function
    DecryptionProfile decryption_profile = matchDecryptionProfile(
        session,
        configuration.decryption_profiles
    );
    DecryptionSession decryption_session = createOrGetDecryptionSession(
        decryptionSessionTable,
        key,
        session,
        decryption_profile
    );
    bool packet_is_last_in_session = sessionTable.isPacketEndingSession(*tcpLayerPacket);
    if (packet_is_last_in_session) {

        if (decryption_profile.shouldDecrypt()) {
            decryptionManager.decrypt_and_enhance_session(decryption_session);
            // TODO somehow fix this iteration, its not working because SecurityProfile is abstract class, not sure how to work around that
            for (SecurityProfile profile : security_profiles_to_apply) {
                Action action = profile.scan(decryption_session, *ipLayerPacket);
            }

        }
    }
    //TODO improve the way of creating sessions and matching policies from configuration, this could be wrapped into some generic function
    NatPolicy nat_policy = matchNatPolicy(
        session,
        configuration.nat_policies
    );
    NatSession nat_session = createOrGetNatSession(
        natSessionTable,
        key,
        session,
        nat_policy
    );
    // TODO implement routing here, there should be some function like route that gets nat_session, the NAT could be implemented either in routing engine itself,
    // TODO in some NAT manager similar in logic to decryptionManager
    // ROUTING SHOULD TAKE PLACE HERE


    if (packet_is_last_in_session) {
        sessionTable.eraseSession(key);
        natSessionTable.eraseSession(key);
        decryptionSessionTable.eraseSession(key);
    }
}

int main() {
    captureInterface = PcapLiveDeviceList::getInstance().getDeviceByName("wlp0s20f3");

    std::signal(SIGINT, exitProgram);
    std::signal(SIGSTOP, exitProgram);

    if (!captureInterface->open()) {
        return 1;
    }
    if (!captureInterface->open()) {
        return 1;
    }

    configuration.load();

    if (!captureInterface->startCapture(onPacketArrives, nullptr)) {
        captureInterface->close();
        return 1;
    }

    while (!stopSignal) {
        std::this_thread::sleep_for(std::chrono::milliseconds(200));
    }

    captureInterface->close();
    std::printf("Capture stopped.\n");
    return 0;
}
