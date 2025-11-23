//
// Created by mikolaj on 11/5/25.
//

#ifndef BASIC_FIREWALL_NAT_POLICY_H
#define BASIC_FIREWALL_NAT_POLICY_H
#include <boost/unordered/unordered_map.hpp>
#include <boost/unordered/unordered_map_fwd.hpp>
#include <boost/unordered_set.hpp>
#include <optional>
#include <vector>


struct NatSessionKey {
    pcpp::IPv4Address src_ip;
    uint16_t          src_port;
    pcpp::IPv4Address dst_ip;
    uint16_t          dst_port;
    uint8_t           protocol;
};

struct NatSessionKeyHash {
    std::size_t operator()(NatSessionKey const& k) const noexcept {
        std::size_t seed = 0;
        boost::hash_combine(seed, k.src_ip.toInt());
        boost::hash_combine(seed, k.src_port);
        boost::hash_combine(seed, k.dst_ip.toInt());
        boost::hash_combine(seed, k.dst_port);
        boost::hash_combine(seed, k.protocol);
        return seed;
    }
};

struct NatSessionKeyEq {
    bool operator()(NatSessionKey const& a, NatSessionKey const& b) const noexcept {
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

class NatTable {
    public:
        using SessionMap = boost::unordered_map<NatSessionKey, NatSession, NatSessionKeyHash, NatSessionKeyEq>;
    private:
        SessionMap sessions_;

    public:
        NatSession* findSession(NatSessionKey const& key);
        NatSession& createSession(NatSessionKey const& key, NatSession session);
        void eraseSession(NatSessionKey const& key);
};

class PortPool {
    private:
        uint16_t start_;
        uint16_t end_;
        std::vector<bool> used_;
        uint16_t next_{0};
    public:
        PortPool(
            uint16_t port_pool_from, uint16_t port_pool_to
        )
            : start_(port_pool_from)
            ,end_(port_pool_to)
            ,used_(port_pool_to - port_pool_from + 1, false)
            ,next_(port_pool_from) {};
        std::optional<uint16_t> acquire_free_port_number();
        void release_port(uint16_t port);
};

class NatState {
    public:
        NatTable  table;
        PortPool  ports;

        NatState(uint16_t port_start, uint16_t port_end)
            : ports(port_start, port_end) {}
        NatSession* getOrCreateSession(const NatSessionKey& key, pcpp::IPv4Address external_ip);
        void removeSession(const NatSessionKey& key);
};

class NatPolicy : public Policy {
    private:
        static NatState nat_state();
        pcpp::IPv4Address translated_source_ip;
        pcpp::IPv4Address translated_destination_ip;

    public:
        NatPolicy(
            std::pmr::string network_from_str,
            uint32_t         from_mask,
            std::pmr::string network_to_str,
            uint32_t         to_mask,
            std::uint16_t    src_port,
            std::uint16_t    dest_port
        ) : Policy(
            std::move(network_from_str),
            from_mask,
            std::move(network_to_str),
            to_mask,
            src_port,
            dest_port
        )
        { };
        static void configureNatState(uint16_t port_start, uint16_t port_end);
};

#endif