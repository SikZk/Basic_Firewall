#include <shared_mutex>
#include "../../../include/session/session_tables/DecryptionSessionTable.h"

DecryptionSessionTable::SessionMap DecryptionSessionTable::decryption_sessions{};

Session& DecryptionSessionTable::createSession(SessionFlowKey const& key, DecryptionSession session) {
    std::unique_lock lock(rw_lock);
    auto [it, _] = decryption_sessions.emplace(key, std::move(session));
    return it->second;
}

Session* DecryptionSessionTable::findSession(SessionFlowKey const& key) {
    std::shared_lock lock(rw_lock);
    auto it = decryption_sessions.find(key);
    return it == decryption_sessions.end() ? nullptr : &it->second;
}

void DecryptionSessionTable::eraseSession(SessionFlowKey const& key) {
    std::unique_lock lock(rw_lock);
    decryption_sessions.erase(key);
}

bool DecryptionSessionTable::doesSessionExist(const SessionFlowKey& key) const {
    std::shared_lock lock(rw_lock);
    return decryption_sessions.find(key) != decryption_sessions.end();
}
