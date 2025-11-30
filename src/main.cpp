// main.cpp
#include "pcapplusplus/PcapLiveDeviceList.h"
#include "pcapplusplus/PcapLiveDevice.h"
#include "pcapplusplus/RawPacket.h"
#include "pcapplusplus/Packet.h"
#include "pcapplusplus/IPv4Layer.h"
#include <cstdio>
#include <csignal>
#include <thread>
#include <chrono>
#include "../include/configuration/Config.h"
#include "./utils.h"
#include "../include/session/session_tables/DecryptionSessionTable.h"
#include "../include/decryption/DecryptionManager.h"
#include "../include/policies/NatService.h"
#include "../include/routing/RoutingEngine.h"

using namespace pcpp;

static PcapLiveDevice* captureInterface = nullptr;
static Config configuration("../resources/config.json");

static volatile std::sig_atomic_t stopSignal = 0;
static SessionTable sessionTable;
static DecryptionSessionTable decryptionSessionTable;
static NatSessionTable natSessionTable;

static RoutingEngine routingEngine;

DecryptionManager decryptionManager;
NatService natService;



static void exitProgram(int) {
    stopSignal = 1;
    if (captureInterface && captureInterface->isOpened()) {
        captureInterface->stopCapture();
    }
}


static void onPacketArrives(RawPacket* rawPacket, PcapLiveDevice*, void*) {
    Packet parsedPacket(rawPacket);
    if (parsedPacket.isPacketOfType(Ethernet)) {
        return;
    }
    IPv4Layer* ipLayerPacket = parsedPacket.getLayerOfType<IPv4Layer>();
    TcpLayer* tcpLayerPacket = parsedPacket.getLayerOfType<TcpLayer>();

    auto security_policy = matchBasedOnObject<IPv4Layer, SecurityPolicy>(
        ipLayerPacket,
        configuration.security_policies
    );
    if (!security_policy.getAllowPacket()) return;
    SessionFlowKey key = getSessionFlowKey(ipLayerPacket, tcpLayerPacket);

    Session* session = createOrGetSession(
     sessionTable,
        key,
        ipLayerPacket,
        tcpLayerPacket,
        captureInterface
    );

    auto decryption_profile = matchBasedOnObject<Session, DecryptionProfile>(
        session,
        configuration.decryption_profiles
    );
    auto nat_policy = matchBasedOnObject<Session, NatPolicy >(
        session,
        configuration.nat_policies
    );
    std::vector<SecurityProfile> security_profiles_to_apply = security_policy.evaluate_security_profiles(*ipLayerPacket);

    Action action = ALLOW;
    if (isNotEncryptedSession(session)) {
        for (SecurityProfile profile : security_profiles_to_apply) {
            action = profile.scan(session, *ipLayerPacket);
        }
    } else if (decryption_profile.shouldDecrypt()) {
        DecryptionSession decryption_session = createOrGetDecryptionSession(
         decryptionSessionTable,
            key,
            session,
            decryption_profile
        );
        decryptionManager.decrypt_and_enhance_session(decryption_session);

        // TODO somehow fix this iteration, its not working because SecurityProfile is abstract class, not sure how to work around that
        for (SecurityProfile profile : security_profiles_to_apply) {
            action = profile.scan(decryption_session, *ipLayerPacket);
        }
    }

    NatSession nat_session = createOrGetNatSession(
        natSessionTable,
        key,
        session,
        nat_policy
    );
    IPv4Layer* translated_packet = natService.applyNat(nat_session, ipLayerPacket);

    // TODO implement routing here, there should be some function like route that gets nat_session, the NAT could be implemented either in routing engine itself,
    // TODO in some NAT manager similar in logic to decryptionManager
    // ROUTING SHOULD TAKE PLACE HERE

    routingEngine.routePacket(translated_packet, ipLayerPacket);

    if (sessionTable.isPacketEndingSession(*tcpLayerPacket)) {
        sessionTable.eraseSession(key);
        natSessionTable.eraseSession(key);
        decryptionSessionTable.eraseSession(key);
    }
}

int main() {
    std::signal(SIGINT, exitProgram);
    std::signal(SIGSTOP, exitProgram);

    configuration.load();
    routingEngine.loadInterfaces(configuration.getCaptureInterfaces());

    for (PcapLiveDevice* interface : configuration.getCaptureInterfaces()) {
        if (!interface->open()) return 1;

        if (!interface->startCapture(onPacketArrives, nullptr)) {
            interface->close();
            return 1;
        }
    }

    while (!stopSignal) {
        std::this_thread::sleep_for(std::chrono::milliseconds(200));
    }

    for (PcapLiveDevice* interface : configuration.getCaptureInterfaces()) {
        interface->close();
    }
    return 0;
}
