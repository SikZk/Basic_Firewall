//
// Created by mikolaj on 11/23/25.
//

#ifndef BASIC_FIREWALL_DECRYPTIONSESSIONTABLE_H
#define BASIC_FIREWALL_DECRYPTIONSESSIONTABLE_H
#include <shared_mutex>
#include <boost/unordered/unordered_map_fwd.hpp>

#include "DecryptionSession.h"
#include "Session.h"

class SessionTable {
private:
    // Używamy boost::unordered_map
    // Key: FlowKey
    // Value: shared_ptr do sesji
    using SessionMap = boost::unordered_map<SessionKey, DecryptionSession, SessionKeyHash, SessionKeyEq>;

    // Blokada Read-Write (zoptymalizowana: wiele wątków czyta, jeden pisze)
    mutable std::shared_mutex rw_lock;

public:
    SessionTable() = default;

    std::shared_ptr<DecryptionSession> getSession(const SessionKey& key);
    std::shared_ptr<DecryptionSession> createSession(const SessionKey& forwardKey);
    void removeSession(const std::shared_ptr<DecryptionSession>& session);


    static bool extractKey(pcpp::Packet& packet, SessionKey& key); // przypisanie wartosci do structa

};

#endif //BASIC_FIREWALL_DECRYPTIONSESSIONTABLE_H