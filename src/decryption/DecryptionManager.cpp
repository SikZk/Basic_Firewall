#include <openssl/ssl.h>
#include "../../include/decryption/DecryptionManager.h"
#include "../../include/session/sessions/DecryptionSession.h"

DecryptionManager::DecryptionManager() : ctx_server(nullptr), ctx_client(nullptr) {}

void DecryptionManager::init() {
    SSL_library_init();
    OpenSSL_add_ssl_algorithms();
    ctx_server = SSL_CTX_new(TLS_method());
    ctx_client = SSL_CTX_new(TLS_method());
}

bool DecryptionManager::processPacket(Session* /*session*/, pcpp::Packet& /*packet*/, std::vector<pcpp::Packet>& /*outPackets*/) {
    return false;
}

void DecryptionManager::decrypt_and_enhance_session(DecryptionSession /*decryption_session*/) {
    // placeholder
}

::SSL* DecryptionManager::createForgedServerSSL(const std::string& /*serverName*/) {
    return ctx_server ? SSL_new(ctx_server) : nullptr;
}
