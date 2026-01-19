#include "../../../include/session/sessions/DecryptionSession.h"
#include <algorithm>
#include <iostream>

DecryptionSession::DecryptionSession(
    pcpp::IPv4Address firewall_interface_ip,
    pcpp::IPv4Address source_ip,
    uint16_t source_port,
    pcpp::IPv4Address destination_ip,
    uint16_t destination_port
)
    : Session(
        firewall_interface_ip,
        firewall_interface_ip,
        source_ip,
        source_port,
        destination_ip,
        destination_port
    ),
      seq_num(0),
      ack_num(0)
{
}

void DecryptionSession::processEncryptedData(const uint8_t* payload, size_t length)
{
    if (payload == nullptr || length == 0) {
        return;
    }
    decrypted_buffer.insert(decrypted_buffer.end(), payload, payload + length);
    std::cout << "[Decryption] Buffered " << length << " bytes (no-op)." << std::endl;
    if (!warned_encrypted) {
        warned_encrypted = true;
        std::cout << "[Decryption] TLS payload still encrypted. Transparent TLS MITM is not implemented yet."
                  << std::endl;
    }
}

bool DecryptionSession::hasCompleteHttpHeader() const
{
    const std::string marker = "\r\n\r\n";
    if (decrypted_buffer.size() < marker.size()) {
        return false;
    }
    return std::search(decrypted_buffer.begin(), decrypted_buffer.end(), marker.begin(), marker.end()) != decrypted_buffer.end();
}

std::string DecryptionSession::getDecryptedDataAsString() const
{
    return std::string(decrypted_buffer.begin(), decrypted_buffer.end());
}

void DecryptionSession::clearBuffer()
{
    decrypted_buffer.clear();
}
