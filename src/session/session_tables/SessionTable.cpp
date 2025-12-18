#include "../../../include/session/session_tables/SessionTable.h"

SessionTable::SessionMap SessionTable::sessions_{};

SessionTable::SessionTable() = default;

Session* SessionTable::findSession(SessionFlowKey const& key) {
    auto it = sessions_.find(key);
    return it == sessions_.end() ? nullptr : &it->second;
}

Session& SessionTable::createSession(SessionFlowKey const& key, Session session) {
    auto [it, _] = sessions_.emplace(key, std::move(session));
    return it->second;
}

void SessionTable::eraseSession(SessionFlowKey const& key) {
    sessions_.erase(key);
}

bool SessionTable::isPacketEndingSession(const pcpp::TcpLayer& tcpLayer) const {
    auto header = tcpLayer.getTcpHeader();
    return header->finFlag || header->rstFlag;
}

bool SessionTable::doesSessionExist(const SessionFlowKey& key) const {
    return sessions_.find(key) != sessions_.end();
}
