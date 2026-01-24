#ifndef BASIC_FIREWALL_DECRYPTIONSESSION_H
#define BASIC_FIREWALL_DECRYPTIONSESSION_H
#include <cstdint>
#include <vector>
#include <openssl/types.h>
#include <pcapplusplus/IpAddress.h>
#include "Session.h"

/**
 * @brief Session that tracks TLS decryption state and buffers.
 */
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
    /**
     * @brief Construct a decryption session.
     *
     * @param firewall_interface_ip Firewall interface IP.
     * @param source_ip Source IP address.
     * @param source_port Source port.
     * @param destination_ip Destination IP address.
     * @param destination_port Destination port.
     */
    DecryptionSession(
        pcpp::IPv4Address firewall_interface_ip,
        pcpp::IPv4Address source_ip,
        uint16_t          source_port,
        pcpp::IPv4Address destination_ip,
        uint16_t          destination_port
    );
    /**
     * @brief Destroy the decryption session.
     */
    ~DecryptionSession() = default;

    /**
     * @brief Feed encrypted payload data into the TLS engine.
     *
     * @param payload Encrypted bytes.
     * @param length Payload length.
     */
    void processEncryptedData(const uint8_t* payload, size_t length);
    /**
     * @brief Feed decrypted payload data into buffers.
     *
     * @param payload Decrypted bytes.
     * @param length Payload length.
     */
    void processDecryptedData(const uint8_t* payload, size_t length);
    /**
     * @brief Determine if a full HTTP header is buffered.
     *
     * @return True if a complete header is present.
     */
    bool hasCompleteHttpHeader() const;
    /**
     * @brief Get decrypted payload as a string.
     *
     * @return Decrypted payload string.
     */
    std::string getDecryptedDataAsString() const;
    /**
     * @brief Clear the decrypted buffer.
     */
    void clearBuffer();
};

#endif
