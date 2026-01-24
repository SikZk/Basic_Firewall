#ifndef BASIC_FIREWALL_NATSESSIONTABLE_H
#define BASIC_FIREWALL_NATSESSIONTABLE_H
#include <optional>
#include <boost/unordered/unordered_map_fwd.hpp>

#include "./SessionTable.h"
#include "../sessions/NatSession.h"
#include "../sessions/Session.h"

/**
 * @brief Table for managing NAT sessions.
 */
class NatSessionTable : public SessionTable {
private:
    using SessionMap = boost::unordered_map<SessionFlowKey, NatSession, SessionKeyHash, SessionKeyEq>;
    static SessionMap nat_sessions;

public:
    /**
     * @brief Create a NAT session entry.
     *
     * @param key Session flow key.
     * @param session NAT session data.
     * @return Reference to the stored session.
     */
    Session& createSession(SessionFlowKey const& key, NatSession session);
    /**
     * @brief Find a NAT session by key.
     *
     * @param key Session flow key.
     * @return Pointer to the session or nullptr.
     */
    Session* findSession(SessionFlowKey const& key);
    /**
     * @brief Remove a NAT session by key.
     *
     * @param key Session flow key.
     */
    void eraseSession(SessionFlowKey const& key);
    /**
     * @brief Check if a NAT session exists.
     *
     * @param key Session flow key.
     * @return True if the session exists.
     */
    bool doesSessionExist(const SessionFlowKey& key) const;
};

/**
 * @brief Simple port pool allocator for NAT.
 */
class PortPool {
private:
    uint16_t start_;
    uint16_t end_;
    std::vector<bool> used_;
    uint16_t next_{0};
public:
    /**
     * @brief Construct a port pool.
     *
     * @param port_pool_from First port in the pool.
     * @param port_pool_to Last port in the pool.
     */
    PortPool(
        uint16_t port_pool_from, uint16_t port_pool_to
    )
        : start_(port_pool_from),
          end_(port_pool_to),
          used_(port_pool_to - port_pool_from + 1, false),
          next_(port_pool_from) {}
    /**
     * @brief Acquire the next free port.
     *
     * @return Optional port number if available.
     */
    std::optional<uint16_t> acquire_free_port_number();
    /**
     * @brief Release a port back to the pool.
     *
     * @param port Port number to release.
     */
    void release_port(uint16_t port);
};

/**
 * @brief Shared NAT state including sessions and port pool.
 */
class NatState {
public:
    NatSessionTable table;
    PortPool ports;

    /**
     * @brief Construct NAT state with port pool bounds.
     *
     * @param port_start First port in the pool.
     * @param port_end Last port in the pool.
     */
    NatState(uint16_t port_start, uint16_t port_end)
        : ports(port_start, port_end) {}
    /**
     * @brief Get or create a NAT session for a flow.
     *
     * @param key Session flow key.
     * @param external_ip External IP to assign.
     * @return Pointer to the NAT session.
     */
    NatSession* getOrCreateSession(const SessionFlowKey& key, pcpp::IPv4Address external_ip);
    /**
     * @brief Remove a NAT session by key.
     *
     * @param key Session flow key.
     */
    void removeSession(const SessionFlowKey& key);
};


#endif
