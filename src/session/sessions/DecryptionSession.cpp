// src/session/sessions/DecryptionSession.cpp

#include "../../../include/session/sessions/DecryptionSession.h"
#include <iostream>

DecryptionSession::DecryptionSession(
    pcpp::IPv4Address firewall_interface_ip,
    pcpp::IPv4Address source_ip,
    uint16_t          source_port,
    pcpp::IPv4Address destination_ip,
    uint16_t          destination_port
) : Session(firewall_interface_ip, firewall_interface_ip, // Simplified assumption
            source_ip, source_port, destination_ip, destination_port),
    seq_num(0), ack_num(0)
{
    // Constructor logic
}

void DecryptionSession::processEncryptedData(const uint8_t* payload, size_t length) {
    // This is called AFTER SSL_read with the plaintext
    decrypted_buffer.insert(decrypted_buffer.end(), payload, payload + length);
}

bool DecryptionSession::hasCompleteHttpHeader() const {
    // Check buffer for double CRLF
    std::string data(decrypted_buffer.begin(), decrypted_buffer.end());
    return data.find("\r\n\r\n") != std::string::npos;
}

std::string DecryptionSession::getDecryptedDataAsString() const {
    return std::string(decrypted_buffer.begin(), decrypted_buffer.end());
}

void DecryptionSession::clearBuffer() {
    decrypted_buffer.clear();
}