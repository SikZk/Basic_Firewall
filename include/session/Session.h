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

struct SessionKey {
    pcpp::IPv4Address src_ip;
    uint16_t          src_port;
    pcpp::IPv4Address dst_ip;
    uint16_t          dst_port;
    uint8_t           protocol;
};

struct SessionKeyHash {
    std::size_t operator()(SessionKey const& k) const noexcept {
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
    bool operator()(SessionKey const& a, SessionKey const& b) const noexcept {
        return a.src_ip      == b.src_ip &&
               a.src_port    == b.src_port &&
               a.dst_ip      == b.dst_ip &&
               a.dst_port    == b.dst_port &&
               a.protocol    == b.protocol;
    }
};

struct NatSession {
    pcpp::IPv4Address internal_ip;
    uint16_t          internal_port;
    pcpp::IPv4Address external_ip;
    uint16_t          external_port;
};

struct DecryptionConnectionLeg {
    uint32_t ip;
    uint16_t port;
    uint32_t seq_num;
    uint32_t ack_num;
    SSL* ssl_handle = nullptr;
    BIO* read_bio = nullptr;
    BIO* write_bio = nullptr;
};

#endif //BASIC_FIREWALL_SESSION_H