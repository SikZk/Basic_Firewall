#include "../../../include/session/session_tables/SessionTable.h"
#include <boost/unordered/unordered_map.hpp>

SessionTable::SessionMap SessionTable::sessions_;

SessionTable::SessionTable() = default;

Session* SessionTable::findSession(SessionFlowKey const& key)
{
    auto it = sessions_.find(key);
    if (it == sessions_.end()) {
        return nullptr;
    }
    return &it->second;
}

Session& SessionTable::createSession(SessionFlowKey const& key, Session session)
{
    auto [it, inserted] = sessions_.emplace(key, std::move(session));
    return it->second;
}

void SessionTable::eraseSession(SessionFlowKey const& key)
{
    sessions_.erase(key);
}

bool SessionTable::isPacketEndingSession(const pcpp::TcpLayer& tcpLayer) const
{
    return tcpLayer.getTcpHeader()->finFlag || tcpLayer.getTcpHeader()->rstFlag;
}

bool SessionTable::doesSessionExist(const SessionFlowKey& key) const
{
    return sessions_.find(key) != sessions_.end();
}
