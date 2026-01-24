#ifndef BASIC_FIREWALL_DECRYPTION_PROFILE_H
#define BASIC_FIREWALL_DECRYPTION_PROFILE_H

#include <string>
#include <pcapplusplus/IpAddress.h>
#include <openssl/evp.h>
#include <openssl/x509.h>
#include "../session/sessions/Session.h"


/**
 * @brief TLS decryption profile with certificate material and match rules.
 */
class DecryptionProfile {
public:
    /** @brief Whether the profile enables decryption. */
    bool should_decrypt;
    /** @brief Human-readable profile name. */
    std::string profile_name;
    /** @brief Path to the CA certificate. */
    std::string ca_certificate_path;
    /** @brief Path to the CA private key. */
    std::string ca_private_key_path;
    /** @brief Loaded CA certificate. */
    X509* ca_cert = nullptr;
    /** @brief Loaded CA private key. */
    EVP_PKEY* ca_private_key = nullptr;
    /**
     * @brief Construct a decryption profile.
     *
     * @param name Profile name.
     * @param ca_cert Path to CA certificate.
     * @param ca_key Path to CA private key.
     * @param from_ip Source network address.
     * @param from_mask Source CIDR mask length.
     * @param to_ip Destination network address.
     * @param to_mask Destination CIDR mask length.
     */
    DecryptionProfile(std::string name,
                      std::string ca_cert, std::string ca_key,
                      std::string from_ip, uint32_t from_mask,
                      std::string to_ip, uint32_t to_mask);

    /**
     * @brief Load certificate and key material from disk.
     *
     * @return True if loaded successfully.
     */
    bool loadCryptoMaterial();
    /**
     * @brief Check if decryption is enabled for this profile.
     *
     * @return True if decryption should be performed.
     */
    bool shouldDecrypt() const;
    /**
     * @brief Determine if the profile matches a session.
     *
     * @param session Session to evaluate.
     * @return True if the session matches this profile.
     */
    bool doesMatchProfile(Session const& session) const;
    /**
     * @brief Determine if endpoints match profile networks.
     *
     * @param source Source IP address.
     * @param destination Destination IP address.
     * @return True if endpoints fall within configured networks.
     */
    bool matchesEndpoints(const pcpp::IPv4Address& source, const pcpp::IPv4Address& destination) const;
    /**
     * @brief Get the loaded CA certificate.
     *
     * @return Pointer to the CA X509 certificate.
     */
    X509* getCaCert() const;
    /**
     * @brief Get the loaded CA private key.
     *
     * @return Pointer to the CA private key.
     */
    EVP_PKEY* getCaPrivateKey() const;

private:
    pcpp::IPv4Address network_from;
    uint32_t network_from_mask;
    pcpp::IPv4Address network_to;
    uint32_t network_to_mask;
};

#endif
