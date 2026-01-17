#include "../../../include/session/session_tables/NatSessionTable.h"
#include <boost/unordered/unordered_map.hpp>

NatSessionTable::SessionMap NatSessionTable::nat_sessions;

Session& NatSessionTable::createSession(SessionFlowKey const& key, NatSession session)
{
    auto it = nat_sessions.find(key);
    if (it != nat_sessions.end()) {
        return it->second;
    }
    auto [insertedIt, inserted] = nat_sessions.emplace(key, std::move(session));
    return insertedIt->second;
}

Session* NatSessionTable::findSession(SessionFlowKey const& key)
{
    auto it = nat_sessions.find(key);
    if (it == nat_sessions.end()) {
        return nullptr;
    }
    return &it->second;
}

NatSession* NatSessionTable::findByNatMapping(
    const pcpp::IPv4Address& nat_ip,
    uint16_t nat_port,
    const pcpp::IPv4Address& external_ip,
    uint16_t external_port
)
{
    for (auto& entry : nat_sessions) {
        auto& session = entry.second;
        const auto& flow = session.getSourceToDestinationFlow();
        if (!session.isSourceNat()) {
            continue;
        }
        if (session.getNatIp() == nat_ip &&
            session.getNatPort() == nat_port &&
            flow.external_ip == external_ip &&
            flow.external_port == external_port) {
            return &session;
        }
    }
    return nullptr;
}

void NatSessionTable::eraseSession(SessionFlowKey const& key)
{
    nat_sessions.erase(key);
}

bool NatSessionTable::doesSessionExist(const SessionFlowKey& key) const
{
    return nat_sessions.find(key) != nat_sessions.end();
}

std::optional<uint16_t> PortPool::acquire_free_port_number()
{
    if (used_.empty()) {
        return std::nullopt;
    }
    for (size_t i = 0; i < used_.size(); ++i) {
        size_t index = (next_ - start_ + i) % used_.size();
        if (!used_[index]) {
            used_[index] = true;
            next_ = static_cast<uint16_t>(start_ + (index + 1) % used_.size());
            return static_cast<uint16_t>(start_ + index);
        }
    }
    return std::nullopt;
}

void PortPool::release_port(uint16_t port)
{
    if (port < start_ || port > end_) {
        return;
    }
    used_[port - start_] = false;
}

NatSession* NatState::getOrCreateSession(const SessionFlowKey& key, pcpp::IPv4Address external_ip)
{
    (void)external_ip;
    auto* existing = static_cast<NatSession*>(table.findSession(key));
    if (existing) {
        return existing;
    }
    auto port = ports.acquire_free_port_number().value_or(0);
    NatSession session(key.src_ip, key.src_port, key.dst_ip, key.dst_port, external_ip, port, true, false);
    auto& stored = table.createSession(key, std::move(session));
    return static_cast<NatSession*>(&stored);
}

void NatState::removeSession(const SessionFlowKey& key)
{
    table.eraseSession(key);
}
