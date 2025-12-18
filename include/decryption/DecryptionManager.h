//
// Created by mikolaj on 11/23/25.
//

#ifndef BASIC_FIREWALL_DECRYPTIONMANAGER_H
#define BASIC_FIREWALL_DECRYPTIONMANAGER_H

#include "../session/sessions/Session.h"
#include "../session/sessions/DecryptionSession.h"
#include <openssl/types.h>
#include <openssl/ssl.h>
#include <pcapplusplus/Packet.h>

class DecryptionManager {
    ::SSL_CTX* ctx_server; // Kontekst, gdy udajemy serwer (dla client_side)
    ::SSL_CTX* ctx_client; // Kontekst, gdy jesteśmy klientem (dla server_side)

public:
    DecryptionManager();
    void init(); // ladowanie certow

    // glowna logika, deszyfracja, szyfracja, ogarniecie czy pakiet jest client-side czy server-side
    bool processPacket(Session* session, pcpp::Packet& packet, std::vector<pcpp::Packet>& outPackets);
    void decrypt_and_enhance_session(const DecryptionSession& decryption_session);

private:
    // Generowanie fałszywego certyfikatu w locie (na podstawie SNI prawdziwego serwera)
    ::SSL* createForgedServerSSL(const std::string& serverName);
};

#endif //BASIC_FIREWALL_DECRYPTIONMANAGER_H
