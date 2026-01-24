#ifndef BASIC_FIREWALL_SESSION_H
#define BASIC_FIREWALL_SESSION_H
#include <boost/container_hash/hash.hpp>
#include <openssl/ssl.h>
#include "pcapplusplus/IPv4Layer.h"
#include "pcapplusplus/TcpLayer.h"

/**
 * @brief State of a tracked session.
 */
enum SessionState {
    HANDSHAKE_INIT,
    ESTABLISHED,
    CLOSING,
    CLOSED
};

/**
 * @brief Key used to identify a session flow.
 */
struct SessionFlowKey {
    pcpp::IPv4Address src_ip;
    uint16_t          src_port;
    pcpp::IPv4Address dst_ip;
    uint16_t          dst_port;
    pcpp::ProtocolType protocol;
};

/**
 * @brief Hash functor for SessionFlowKey.
 */
struct SessionKeyHash {
    /**
     * @brief Compute a hash for a session key.
     *
     * @param k Session flow key.
     * @return Hash value.
     */
    std::size_t operator()(SessionFlowKey const& k) const noexcept {
        std::size_t seed = 0;
        boost::hash_combine(seed, k.src_ip.toInt());
        boost::hash_combine(seed, k.src_port);
        boost::hash_combine(seed, k.dst_ip.toInt());
        boost::hash_combine(seed, k.dst_port);
        boost::hash_combine(seed, k.protocol);
        return seed;
    }
};

/**
 * @brief Equality comparator for SessionFlowKey.
 */
struct SessionKeyEq {
    /**
     * @brief Compare two session keys.
     *
     * @param a First key.
     * @param b Second key.
     * @return True if keys are identical.
     */
    bool operator()(SessionFlowKey const& a, SessionFlowKey const& b) const noexcept {
        return a.src_ip      == b.src_ip &&
               a.src_port    == b.src_port &&
               a.dst_ip      == b.dst_ip &&
               a.dst_port    == b.dst_port &&
               a.protocol    == b.protocol;
    }
};

/**
 * @brief Directional flow tuple for a session.
 */
struct SessionFlow {
    pcpp::IPv4Address internal_ip;
    uint16_t          internal_port;
    pcpp::IPv4Address external_ip;
    uint16_t          external_port;
};

/**
 * @brief Base session tracking data for a flow.
 */
class Session {
protected:
    SessionFlow source_to_destination;
    SessionFlow destination_to_source;
    SessionState session_state;
    uint8_t* data;
    size_t data_length = 0;
    size_t data_capacity = 0;

public:
    /**
     * @brief Construct a session for a flow.
     *
     * @param firewall_interface_src_ip Firewall interface IP (source).
     * @param firewall_interface_dest_ip Firewall interface IP (destination).
     * @param source_ip Source IP address.
     * @param source_port Source port.
     * @param destination_ip Destination IP address.
     * @param destination_port Destination port.
     */
    Session(
        pcpp::IPv4Address firewall_interface_src_ip,
        pcpp::IPv4Address firewall_interface_dest_ip,
        pcpp::IPv4Address source_ip,
        uint16_t source_port,
        pcpp::IPv4Address destination_ip,
        uint16_t destination_port
    );
    /**
     * @brief Destroy the session.
     */
    ~Session() = default;
    /**
     * @brief Generate a session flow key.
     *
     * @param source_ip Source IP address.
     * @param source_port Source port.
     * @param destination_ip Destination IP address.
     * @param destination_port Destination port.
     * @return Session flow key.
     */
    static SessionFlowKey generateSessionFlowKey(
        pcpp::IPv4Address source_ip,
        uint16_t source_port,
        pcpp::IPv4Address destination_ip,
        uint16_t destination_port
    );
    /**
     * @brief Get the internal session buffer.
     *
     * @return Pointer to session data buffer.
     */
    uint8_t* getData();
    /**
     * @brief Get the length of buffered session data.
     *
     * @return Buffer length in bytes.
     */
    size_t getDataLength();
    /**
     * @brief Append payload data to the session buffer.
     *
     * @param new_data Data to append.
     * @param length Length of data.
     */
    void appendData(const uint8_t* new_data, size_t length);
    /**
     * @brief Get the source-to-destination flow tuple.
     *
     * @return Reference to the source-to-destination flow.
     */
    const SessionFlow& getSourceToDestinationFlow() const;
    /**
     * @brief Get the destination-to-source flow tuple.
     *
     * @return Reference to the destination-to-source flow.
     */
    const SessionFlow& getDestinationToSourceFlow() const;
};

#endif
