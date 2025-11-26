//
// Created by mikolaj on 11/5/25.
//

#ifndef BASIC_FIREWALL_SESSION_H
#define BASIC_FIREWALL_SESSION_H
#include <boost/container_hash/hash.hpp>
#include <openssl/ssl.h>
#include "pcapplusplus/IPv4Layer.h"
#include "pcapplusplus/TcpLayer.h"

enum SessionState {
    HANDSHAKE_INIT,
    ESTABLISHED,
    CLOSING,
    CLOSED
};


// Tutaj mamy klucz do naszej mapy z sesjami, nasza sesja jest właściwie dwoma Flowami 1) client1->firewall 2) firewall->client2,
// jednak klucz jest tylko jeden i identyfikuje oba Flowy, bo klucz pomija firewalla
struct SessionFlowKey {
    pcpp::IPv4Address src_ip;
    uint16_t          src_port;
    pcpp::IPv4Address dst_ip;
    uint16_t          dst_port;
    uint8_t           protocol;
};

struct SessionKeyHash {
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

struct SessionKeyEq {
    bool operator()(SessionFlowKey const& a, SessionFlowKey const& b) const noexcept {
        return a.src_ip      == b.src_ip &&
               a.src_port    == b.src_port &&
               a.dst_ip      == b.dst_ip &&
               a.dst_port    == b.dst_port &&
               a.protocol    == b.protocol;
    }
};

struct SessionFlow {
    pcpp::IPv4Address internal_ip;
    uint16_t          internal_port;
    pcpp::IPv4Address external_ip;
    uint16_t          external_port;
};

class Session {
    private:
        SessionFlow source_to_destination;
        SessionFlow destination_to_source;
        SessionState session_state;
    public:
        Session(
            pcpp::IPv4Address firewall_interface_src_ip,
            pcpp::IPv4Address firewall_interface_dest_ip,
            pcpp::IPv4Address source_ip,
            uint16_t          source_port,
            pcpp::IPv4Address destination_ip,
            uint16_t          destination_port
        );
        ~Session() = default;
        static SessionFlowKey generateSessionFlowKey(
            pcpp::IPv4Address source_ip,
            uint16_t          source_port,
            pcpp::IPv4Address destination_ip,
            uint16_t          destination_port
        );

};



#endif //BASIC_FIREWALL_SESSION_H