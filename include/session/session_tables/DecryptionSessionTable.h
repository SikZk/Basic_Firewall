#ifndef BASIC_FIREWALL_DECRYPTIONSESSIONTABLE_H
#define BASIC_FIREWALL_DECRYPTIONSESSIONTABLE_H
#include <shared_mutex>
#include <boost/unordered/unordered_map_fwd.hpp>

#include "./SessionTable.h"
#include "../sessions/Session.h"
#include "../sessions/DecryptionSession.h"

class DecryptionSessionTable : public SessionTable {
private:
    using SessionMap = boost::unordered_map<SessionFlowKey, DecryptionSession, SessionKeyHash, SessionKeyEq>;
    static SessionMap decryption_sessions;
    mutable std::shared_mutex rw_lock;

public:
    Session& createSession(SessionFlowKey const& key, DecryptionSession session);
    Session* findSession(SessionFlowKey const& key);
    void eraseSession(SessionFlowKey const& key);
    bool doesSessionExist(const SessionFlowKey& key) const;

};

#endif
