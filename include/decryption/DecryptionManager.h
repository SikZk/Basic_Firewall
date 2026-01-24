#ifndef BASIC_FIREWALL_DECRYPTIONMANAGER_H
#define BASIC_FIREWALL_DECRYPTIONMANAGER_H

#include "../session/sessions/Session.h"
#include "../session/sessions/DecryptionSession.h"
#include <openssl/types.h>
#include <pcapplusplus/Packet.h>

class DecryptionManager {
    ::SSL_CTX* ctx_server;
    ::SSL_CTX* ctx_client;

public:
    DecryptionManager();
    void init();

    bool processPacket(Session* session, pcpp::Packet& packet, std::vector<pcpp::Packet>& outPackets);
    void decrypt_and_enhance_session(DecryptionSession decryption_session);

private:
    ::SSL* createForgedServerSSL(const std::string& serverName);
};

#endif
