// src/decryption/DecryptionManager.cpp

#include "../../include/decryption/DecryptionManager.h"
#include "../../include/session/sessions/DecryptionSession.h"
#include "../../include/decryption/DecryptionProfile.h" // Assuming you have this
#include "pcapplusplus/TcpLayer.h"
#include "pcapplusplus/IPv4Layer.h"
#include <openssl/err.h>
#include <openssl/x509v3.h>
#include <openssl/pem.h>
#include <iostream>

// --- Helper Functions ---
void logSslError(const std::string& context) {
    char buf[256];
    ERR_error_string_n(ERR_get_error(), buf, sizeof(buf));
    std::cerr << "[SSL Error] " << context << ": " << buf << std::endl;
}

// --- DecryptionManager Implementation ---

DecryptionManager::DecryptionManager() : ctx_server(nullptr), ctx_client(nullptr) {}

void DecryptionManager::init() {
    // 1. Initialize OpenSSL Library
    SSL_library_init();
    OpenSSL_add_all_algorithms();
    SSL_load_error_strings();

    // 2. Client Context (Used when FW talks to Real Server)
    ctx_client = SSL_CTX_new(TLS_client_method());
    if (!ctx_client) logSslError("Init ctx_client");
    SSL_CTX_set_default_verify_paths(ctx_client); // Trust system CAs

    // 3. Server Context (Used when FW talks to Client)
    ctx_server = SSL_CTX_new(TLS_server_method());
    if (!ctx_server) logSslError("Init ctx_server");

    // NOTE: You must load your Root CA here for ctx_server so it can sign forged certs!
    // In a real app, load these paths from Config.h
    // SSL_CTX_use_certificate_file(ctx_server, "ca.crt", SSL_FILETYPE_PEM);
    // SSL_CTX_use_PrivateKey_file(ctx_server, "ca.key", SSL_FILETYPE_PEM);
}

::SSL* DecryptionManager::createForgedServerSSL(const std::string& serverName) {
    // 1. Create a new SSL object acting as a server
    SSL* ssl = SSL_new(ctx_server);
    if (!ssl) return nullptr;

    // 2. Generate a fake certificate (Simplified)
    // In production, you would fetch the CA Key from Config/Profile to sign this.
    X509* cert = X509_new();
    EVP_PKEY* pkey = EVP_PKEY_new();
    RSA* rsa = RSA_generate_key(2048, RSA_F4, nullptr, nullptr);
    EVP_PKEY_assign_RSA(pkey, rsa);

    // Set Serial & Time
    ASN1_INTEGER_set(X509_get_serialNumber(cert), 1);
    X509_gmtime_adj(X509_get_notBefore(cert), 0);
    X509_gmtime_adj(X509_get_notAfter(cert), 31536000L);

    // Set Subject SNI
    X509_NAME* name = X509_get_subject_name(cert);
    X509_NAME_add_entry_by_txt(name, "CN", MBSTRING_ASC, (unsigned char*)serverName.c_str(), -1, -1, 0);
    X509_set_issuer_name(cert, name); // Self-signed (Fix this to sign with CA in future!)
    X509_set_pubkey(cert, pkey);

    // Sign (Self-signed for now)
    X509_sign(cert, pkey, EVP_sha256());

    SSL_use_certificate(ssl, cert);
    SSL_use_PrivateKey(ssl, pkey);

    X509_free(cert);
    // EVP_PKEY is handled by SSL structure now
    return ssl;
}

void DecryptionManager::decrypt_and_enhance_session(DecryptionSession decryption_session) {
    // This method might be used for setup, but since we process packet-by-packet,
    // logic is mostly in processPacket.
}

bool DecryptionManager::processPacket(Session* session, pcpp::Packet& packet, std::vector<pcpp::Packet>& outPackets) {
    // 1. Downcast to DecryptionSession
    // dynamic_cast is safer, but requires RTTI. Ensure Session has virtual methods.
    auto* dSession = dynamic_cast<DecryptionSession*>(session);
    if (!dSession) return false;

    // 2. Check for TCP
    auto* tcpLayer = packet.getLayerOfType<pcpp::TcpLayer>();
    auto* ipLayer = packet.getLayerOfType<pcpp::IPv4Layer>();
    if (!tcpLayer || !ipLayer) return false;

    // 3. Identify Direction
    bool isClientToFw = (ipLayer->getSrcIPv4Address() == dSession->source_to_destination.internal_ip); // Assuming internal is client

    // 4. Initialize SSL objects if this is the start of the session
    if (dSession->ssl_client_side == nullptr) {
        // Initialize Client-Side (We act as Server)
        // Note: Real SNI parsing from packet is needed here normally.
        dSession->ssl_client_side = createForgedServerSSL("google.com");
        dSession->client_read_bio = BIO_new(BIO_s_mem());
        dSession->client_write_bio = BIO_new(BIO_s_mem());
        SSL_set_bio(dSession->ssl_client_side, dSession->client_read_bio, dSession->client_write_bio);
        SSL_set_accept_state(dSession->ssl_client_side); // Server Mode

        // Initialize Server-Side (We act as Client)
        dSession->ssl_server_side = SSL_new(ctx_client);
        dSession->server_read_bio = BIO_new(BIO_s_mem());
        dSession->server_write_bio = BIO_new(BIO_s_mem());
        SSL_set_bio(dSession->ssl_server_side, dSession->server_read_bio, dSession->server_write_bio);
        SSL_set_connect_state(dSession->ssl_server_side); // Client Mode
    }

    // 5. Select the Active SSL Object and BIOs based on direction
    SSL* activeSSL = isClientToFw ? dSession->ssl_client_side : dSession->ssl_server_side;
    SSL* targetSSL = isClientToFw ? dSession->ssl_server_side : dSession->ssl_client_side;

    // The "Write BIO" of the active SSL is where we put encrypted packet data
    BIO* inputBIO = BIO_get_rbio(activeSSL);
    // The "Read BIO" of the active SSL is where we get data TO SEND BACK (handshakes/ACKs)
    BIO* outputBIO = BIO_get_wbio(activeSSL);

    // 6. Write Packet Payload into OpenSSL
    uint8_t* payload = tcpLayer->getLayerPayload();
    size_t payloadLen = tcpLayer->getLayerPayloadSize();

    if (payloadLen > 0) {
        BIO_write(inputBIO, payload, payloadLen);
    }

    // 7. Attempt Decryption
    char buf[4096];
    int readBytes = SSL_read(activeSSL, buf, sizeof(buf));

    if (readBytes > 0) {
        // --- DECRYPTION SUCCESSFUL ---
        // Store decrypted data for inspection
        dSession->processEncryptedData((uint8_t*)buf, readBytes);

        // --- RE-ENCRYPTION ---
        // Write the plaintext into the TARGET SSL to be re-encrypted
        SSL_write(targetSSL, buf, readBytes);
    }

    // 8. Drain Output BIOs and Create Packets
    // We might have generated Handshake data OR Re-encrypted application data.
    // We need to check BOTH sides for data to send out.

    // Helper lambda to drain a bio and make a packet
    auto drainAndPacketize = [&](SSL* ssl, bool sendingToClient) {
         BIO* wbio = BIO_get_wbio(ssl);
         int pending = BIO_pending(wbio);
         if (pending > 0) {
             std::vector<uint8_t> encryptedData(pending);
             BIO_read(wbio, encryptedData.data(), pending);

             // Clone original packet to preserve headers (Mac/IP/Ports)
             pcpp::Packet newPacket(packet);

             // Swap Src/Dst if we are sending BACK (e.g. handshake reply)
             // This logic depends heavily on whether we are forwarding or replying.
             // For simplicity: We overwrite the payload of the current flow direction.

             auto* newTcp = newPacket.getLayerOfType<pcpp::TcpLayer>();
             // Only set payload if we are forwarding logic.
             // Ideally you create a fresh packet here based on session IPs.
             newTcp->setLayerPayload(encryptedData.data(), pending);

             // Recompute checksums
             newTcp->computeCalculateFields();
             newPacket.getLayerOfType<pcpp::IPv4Layer>()->computeCalculateFields();

             outPackets.push_back(newPacket);
         }
    };

    // If we received from Client, we might have data to send to Server (Forwarding)
    if (isClientToFw) {
        drainAndPacketize(dSession->ssl_server_side, false); // Send to Server
        drainAndPacketize(dSession->ssl_client_side, true);  // Send back to Client (Handshake?)
    } else {
        drainAndPacketize(dSession->ssl_client_side, true);  // Send to Client
        drainAndPacketize(dSession->ssl_server_side, false); // Send back to Server (Handshake?)
    }

    return true;
}