//
// Created by mikolaj on 11/23/25.
//

#ifndef BASIC_FIREWALL_DECRYPTIONSESSIONTABLE_H
#define BASIC_FIREWALL_DECRYPTIONSESSIONTABLE_H
#include <shared_mutex>
#include <boost/unordered/unordered_map_fwd.hpp>

#include "./SessionTable.h"
#include "../sessions/Session.h"
#include "../sessions/DecryptionSession.h"

class DecryptionSessionTable : public SessionTable{
private:
    mutable std::shared_mutex rw_lock;
public:
    Session& createSession(SessionFlowKey const& key, DecryptionSession session) override;

};

#endif