#ifndef BASIC_FIREWALL_DECRYPTIONSESSIONTABLE_H
#define BASIC_FIREWALL_DECRYPTIONSESSIONTABLE_H
#include <shared_mutex>
#include <boost/unordered/unordered_map_fwd.hpp>

#include "./SessionTable.h"
#include "../sessions/Session.h"
#include "../sessions/DecryptionSession.h"

/**
 * @brief Table for managing decryption sessions.
 */
class DecryptionSessionTable : public SessionTable {
private:
    using SessionMap = boost::unordered_map<SessionFlowKey, DecryptionSession, SessionKeyHash, SessionKeyEq>;
    static SessionMap decryption_sessions;
    mutable std::shared_mutex rw_lock;

public:
    /**
     * @brief Create a decryption session entry.
     *
     * @param key Session flow key.
     * @param session Decryption session data.
     * @return Reference to the stored session.
     */
    Session& createSession(SessionFlowKey const& key, DecryptionSession session);
    /**
     * @brief Find a decryption session by key.
     *
     * @param key Session flow key.
     * @return Pointer to the session or nullptr.
     */
    Session* findSession(SessionFlowKey const& key);
    /**
     * @brief Remove a decryption session by key.
     *
     * @param key Session flow key.
     */
    void eraseSession(SessionFlowKey const& key);
    /**
     * @brief Check if a decryption session exists.
     *
     * @param key Session flow key.
     * @return True if the session exists.
     */
    bool doesSessionExist(const SessionFlowKey& key) const;

};

#endif
