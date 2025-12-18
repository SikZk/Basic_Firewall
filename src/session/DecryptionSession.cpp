#include "../../include/session/sessions/DecryptionSession.h"

DecryptionSession::DecryptionSession(
    pcpp::IPv4Address firewall_interface_ip,
    pcpp::IPv4Address source_ip,
    uint16_t          source_port,
    pcpp::IPv4Address destination_ip,
    uint16_t          destination_port
)
    : Session(firewall_interface_ip, firewall_interface_ip, source_ip, source_port, destination_ip, destination_port)
    , seq_num(0)
    , ack_num(0) {}

void DecryptionSession::processEncryptedData(const uint8_t* payload, size_t length) {
    decrypted_buffer.insert(decrypted_buffer.end(), payload, payload + length);
}

bool DecryptionSession::hasCompleteHttpHeader() const {
    std::string data_str(decrypted_buffer.begin(), decrypted_buffer.end());
    return data_str.find("\r\n\r\n") != std::string::npos;
}

std::string DecryptionSession::getDecryptedDataAsString() const {
    return std::string(decrypted_buffer.begin(), decrypted_buffer.end());
}

void DecryptionSession::clearBuffer() {
    decrypted_buffer.clear();
}
