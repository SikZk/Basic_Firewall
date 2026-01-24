#ifndef BASIC_FIREWALL_SESSIONTABLE_H
#define BASIC_FIREWALL_SESSIONTABLE_H
#include <boost/unordered/unordered_map_fwd.hpp>
#include <pcapplusplus/TcpLayer.h>
#include "../sessions/Session.h"

/**
 * @brief Table for storing active sessions.
 */
class SessionTable {
public:
    /** @brief Map type for session storage. */
    using SessionMap = boost::unordered_map<SessionFlowKey, Session, SessionKeyHash, SessionKeyEq>;

private:
    static SessionMap sessions_;

public:
    /**
     * @brief Construct a session table.
     */
    SessionTable();
    /**
     * @brief Find a session by key.
     *
     * @param key Session flow key.
     * @return Pointer to the session or nullptr.
     */
    Session* findSession(SessionFlowKey const& key);
    /**
     * @brief Create a session entry.
     *
     * @param key Session flow key.
     * @param session Session data to insert.
     * @return Reference to the stored session.
     */
    virtual Session& createSession(SessionFlowKey const& key, Session session);
    /**
     * @brief Remove a session by key.
     *
     * @param key Session flow key.
     */
    void eraseSession(SessionFlowKey const& key);
    /**
     * @brief Determine if a TCP packet ends a session.
     *
     * @param tcpLayer TCP layer to check.
     * @return True if the packet ends the session.
     */
    bool isPacketEndingSession(const pcpp::TcpLayer& tcpLayer) const;
    /**
     * @brief Check if a session exists.
     *
     * @param key Session flow key.
     * @return True if a session exists.
     */
    bool doesSessionExist(const SessionFlowKey& key) const;
};

#endif
