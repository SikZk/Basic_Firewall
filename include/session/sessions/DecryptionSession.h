//
// Created by mikolaj on 11/26/25.
//

#ifndef BASIC_FIREWALL_DECRYPTIONSESSION_H
#define BASIC_FIREWALL_DECRYPTIONSESSION_H
#include <cstdint>
#include <vector>
#include <openssl/types.h>
#include <pcapplusplus/IpAddress.h>
#include "Session.h"

class DecryptionSession : public Session {
private:
    uint32_t seq_num;
    uint32_t ack_num;
    SSL* ssl_client_side = nullptr;
    BIO* client_read_bio = nullptr;
    BIO* client_write_bio = nullptr;

    SSL* ssl_server_side = nullptr;
    BIO* server_read_bio = nullptr;
    BIO* server_write_bio = nullptr;
    std::vector<uint8_t> decrypted_buffer;
    bool warned_encrypted = false;
public:
    DecryptionSession(
        pcpp::IPv4Address firewall_interface_ip,
        pcpp::IPv4Address source_ip,
        uint16_t          source_port,
        pcpp::IPv4Address destination_ip,
        uint16_t          destination_port
    );
    ~DecryptionSession() = default;

    void processEncryptedData(const uint8_t* payload, size_t length);
    void processDecryptedData(const uint8_t* payload, size_t length);
    bool hasCompleteHttpHeader() const;
    std::string getDecryptedDataAsString() const;
    void clearBuffer();

};

#endif //BASIC_FIREWALL_DECRYPTIONSESSION_H
