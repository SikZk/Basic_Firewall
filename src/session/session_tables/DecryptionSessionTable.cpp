#include "../../../include/session/session_tables/DecryptionSessionTable.h"
#include <boost/unordered/unordered_map.hpp>

DecryptionSessionTable::SessionMap DecryptionSessionTable::decryption_sessions;

Session& DecryptionSessionTable::createSession(SessionFlowKey const& key, DecryptionSession session)
{
    std::unique_lock lock(rw_lock);
    auto it = decryption_sessions.find(key);
    if (it != decryption_sessions.end()) {
        return it->second;
    }
    auto [insertedIt, inserted] = decryption_sessions.emplace(key, std::move(session));
    return insertedIt->second;
}

Session* DecryptionSessionTable::findSession(SessionFlowKey const& key)
{
    std::shared_lock lock(rw_lock);
    auto it = decryption_sessions.find(key);
    if (it == decryption_sessions.end()) {
        return nullptr;
    }
    return &it->second;
}

void DecryptionSessionTable::eraseSession(SessionFlowKey const& key)
{
    std::unique_lock lock(rw_lock);
    decryption_sessions.erase(key);
}

bool DecryptionSessionTable::doesSessionExist(const SessionFlowKey& key) const
{
    std::shared_lock lock(rw_lock);
    return decryption_sessions.find(key) != decryption_sessions.end();
}
