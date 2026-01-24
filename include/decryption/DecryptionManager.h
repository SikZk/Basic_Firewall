#ifndef BASIC_FIREWALL_DECRYPTIONMANAGER_H
#define BASIC_FIREWALL_DECRYPTIONMANAGER_H

#include "../session/sessions/Session.h"
#include "../session/sessions/DecryptionSession.h"
#include <openssl/types.h>
#include <pcapplusplus/Packet.h>

/**
 * @brief Manages TLS decryption operations and packet processing.
 */
class DecryptionManager {
    ::SSL_CTX* ctx_server;
    ::SSL_CTX* ctx_client;

public:
    /**
     * @brief Construct a decryption manager.
     */
    DecryptionManager();
    /**
     * @brief Initialize TLS contexts.
     */
    void init();

    /**
     * @brief Process a packet for decryption.
     *
     * @param session Session associated with the packet.
     * @param packet Packet to process.
     * @param outPackets Output packet list for modified packets.
     * @return True if processing succeeded.
     */
    bool processPacket(Session* session, pcpp::Packet& packet, std::vector<pcpp::Packet>& outPackets);
    /**
     * @brief Enhance a session with decryption state.
     *
     * @param decryption_session Session to enhance.
     */
    void decrypt_and_enhance_session(DecryptionSession decryption_session);

private:
    /**
     * @brief Create a forged server SSL context for MITM.
     *
     * @param serverName Server name for certificate generation.
     * @return SSL object for server-side TLS.
     */
    ::SSL* createForgedServerSSL(const std::string& serverName);
};

#endif
