// src/decryption/DecryptionManager.cpp

#include "../../include/decryption/DecryptionManager.h"
#include <iostream>

DecryptionManager::DecryptionManager() : ctx_server(nullptr), ctx_client(nullptr) {}

void DecryptionManager::init()
{
    std::cout << "[Decryption] Initialization skipped (no-op)." << std::endl;
}

::SSL* DecryptionManager::createForgedServerSSL(const std::string&)
{
    return nullptr;
}

void DecryptionManager::decrypt_and_enhance_session(DecryptionSession)
{
    std::cout << "[Decryption] Skipping decryption session enhancement (no-op)." << std::endl;
}

bool DecryptionManager::processPacket(Session*, pcpp::Packet&, std::vector<pcpp::Packet>&)
{
    std::cout << "[Decryption] Skipping packet processing (no-op)." << std::endl;
    return false;
}
