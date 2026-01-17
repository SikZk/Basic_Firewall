//
// Created by mikolaj on 11/23/25.
//

#ifndef BASIC_FIREWALL_NATSESSIONTABLE_H
#define BASIC_FIREWALL_NATSESSIONTABLE_H
#include <optional>
#include <unordered_map>
#include <boost/unordered/unordered_map_fwd.hpp>

#include "./SessionTable.h"
#include "../sessions/NatSession.h"
#include "../sessions/Session.h"

class NatSessionTable : public SessionTable{
    private:
        using SessionMap = boost::unordered_map<SessionFlowKey, NatSession, SessionKeyHash, SessionKeyEq>;
        static SessionMap nat_sessions;
    public:

        Session& createSession(SessionFlowKey const& key, NatSession session);
        Session* findSession(SessionFlowKey const& key);
        void eraseSession(SessionFlowKey const& key);
        bool doesSessionExist(const SessionFlowKey& key) const;
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
    NatSessionTable  table;
    PortPool  ports;
    std::unordered_map<SessionFlowKey, SessionFlowKey, SessionKeyHash, SessionKeyEq> reverse_map;

    NatState(uint16_t port_start, uint16_t port_end)
        : ports(port_start, port_end) {}
    NatSession* getOrCreateSession(const SessionFlowKey& key, pcpp::IPv4Address external_ip);
    NatSession* findByTranslatedKey(const SessionFlowKey& key);
    void removeSession(const SessionFlowKey& key);
};


#endif
