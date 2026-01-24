#ifndef BASIC_FIREWALL_SECURITYPROFILE_H
#define BASIC_FIREWALL_SECURITYPROFILE_H
#include <string>
#include <pcapplusplus/IPv4Layer.h>

#include "../session/sessions/DecryptionSession.h"
#include "../session/sessions/Session.h"
/**
 * @brief Actions returned by security profile scans.
 */
enum Action {
    ALLOW,
    BLOCK,
    ALERT
};

/**
 * @brief Base interface for security profiles.
 */
class SecurityProfile {
public:
    /**
     * @brief Virtual destructor for safe polymorphic deletion.
     */
    virtual ~SecurityProfile() = default;

    /**
     * @brief Constructs a security profile.
     */
    SecurityProfile();

    /**
     * @brief Scan a plaintext packet for policy violations.
     *
     * @param session Active session associated with the packet.
     * @param packet IPv4 packet layer to inspect.
     * @return Action indicating allow/block/alert decision.
     */
    virtual Action scan(Session* session, const pcpp::IPv4Layer& packet) = 0;
    /**
     * @brief Scan a decrypted packet for policy violations.
     *
     * @param session Decryption session carrying decrypted payloads.
     * @param ipv4_packet IPv4 packet layer to inspect.
     * @return Action indicating allow/block/alert decision.
     */
    virtual Action scan(const DecryptionSession&, const pcpp::IPv4Layer& ipv4_packet) = 0;

};

#endif
