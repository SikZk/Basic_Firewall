//
// Created by mikolaj on 11/23/25.
//

#ifndef BASIC_FIREWALL_NATSESSIONTABLE_H
#define BASIC_FIREWALL_NATSESSIONTABLE_H
#include <boost/unordered/unordered_map_fwd.hpp>
#include "./Session.h"

class NatSessionTable {
public:
    using SessionMap = boost::unordered_map<SessionKey, NatSession, SessionKeyHash, SessionKeyEq>;
private:
    SessionMap sessions_;

public:
    NatSession* findSession(SessionKey const& key);
    NatSession& createSession(SessionKey const& key, NatSession session);
    void eraseSession(SessionKey const& key);
};

#endif //BASIC_FIREWALL_NATSESSIONTABLE_H