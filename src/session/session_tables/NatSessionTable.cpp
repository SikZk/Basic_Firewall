#include "../../../include/session/session_tables/NatSessionTable.h"

NatSessionTable::SessionMap NatSessionTable::nat_sessions{};

Session& NatSessionTable::createSession(SessionFlowKey const& key, NatSession session) {
    auto [it, _] = nat_sessions.emplace(key, std::move(session));
    return it->second;
}

Session* NatSessionTable::findSession(SessionFlowKey const& key) {
    auto it = nat_sessions.find(key);
    return it == nat_sessions.end() ? nullptr : &it->second;
}

void NatSessionTable::eraseSession(SessionFlowKey const& key) {
    nat_sessions.erase(key);
}

bool NatSessionTable::doesSessionExist(const SessionFlowKey& key) const {
    return nat_sessions.find(key) != nat_sessions.end();
}

std::optional<uint16_t> PortPool::acquire_free_port_number() {
    for (uint16_t port = start_; port <= end_; ++port) {
        if (!used_[port - start_]) {
            used_[port - start_] = true;
            return port;
        }
    }
    return std::nullopt;
}

void PortPool::release_port(uint16_t port) {
    if (port < start_ || port > end_) return;
    used_[port - start_] = false;
}

NatSession* NatState::getOrCreateSession(const SessionFlowKey& key, pcpp::IPv4Address external_ip) {
    if (auto* existing = table.findSession(key)) {
        return static_cast<NatSession*>(existing);
    }
    auto port_opt = ports.acquire_free_port_number();
    if (!port_opt) return nullptr;
    NatSession nat_session(external_ip, key.src_ip, key.src_port, key.dst_ip, key.dst_port, external_ip, *port_opt, true);
    return static_cast<NatSession*>(&table.createSession(key, std::move(nat_session)));
}

void NatState::removeSession(const SessionFlowKey& key) {
    auto* session = dynamic_cast<NatSession*>(table.findSession(key));
    if (session != nullptr) {
        ports.release_port(session->nat_port);
    }
    table.eraseSession(key);
}
