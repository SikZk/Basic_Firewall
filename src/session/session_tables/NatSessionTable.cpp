#include "../../../include/session/session_tables/NatSessionTable.h"
#include <boost/unordered/unordered_map.hpp>
#include <iostream>

// --- NatSessionTable Implementation ---

NatSessionTable::SessionMap NatSessionTable::nat_sessions;

Session& NatSessionTable::createSession(SessionFlowKey const& key, NatSession session)
{
    auto [it, inserted] = nat_sessions.emplace(key, std::move(session));
    return it->second;
}

Session* NatSessionTable::findSession(SessionFlowKey const& key)
{
    auto it = nat_sessions.find(key);
    if (it == nat_sessions.end()) {
        return nullptr;
    }
    return &it->second;
}

void NatSessionTable::eraseSession(SessionFlowKey const& key)
{
    nat_sessions.erase(key);
}

bool NatSessionTable::doesSessionExist(const SessionFlowKey& key) const
{
    return nat_sessions.find(key) != nat_sessions.end();
}


// --- PortPool Implementation ---

std::optional<uint16_t> PortPool::acquire_free_port_number()
{
    if (used_.empty()) {
        return std::nullopt;
    }
    for (size_t i = 0; i < used_.size(); ++i) {
        size_t index = (next_ - start_ + i) % used_.size();
        if (!used_[index]) {
            used_[index] = true;
            uint16_t allocated = static_cast<uint16_t>(start_ + index);
            next_ = static_cast<uint16_t>(start_ + (index + 1) % used_.size());
            return allocated;
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


// --- NatState Implementation ---

NatSession* NatState::getOrCreateSession(const SessionFlowKey& key, pcpp::IPv4Address external_ip)
{
    // 1. Check if session exists (Outbound)
    if (Session* existing = table.findSession(key)) {
        return static_cast<NatSession*>(existing);
    }

    // 2. Acquire a new port
    auto portOpt = ports.acquire_free_port_number();
    if (!portOpt.has_value()) {
        std::cerr << "[NAT] Error: No free ports available!" << std::endl;
        return nullptr;
    }
    uint16_t allocatedPort = portOpt.value();

    // 3. Create Session Object
    NatSession session(
        external_ip,        // firewall_interface_ip
        key.src_ip,         // source_ip (Internal Client)
        key.src_port,       // source_port
        key.dst_ip,         // destination_ip (External Server)
        key.dst_port,       // destination_port
        external_ip,        // nat_ip
        allocatedPort,      // nat_port
        true                // is_source_nat
    );

    // 4. Insert OUTBOUND key
    Session& storedRef = table.createSession(key, session);

    // 5. Insert INBOUND key (Return Traffic)
    SessionFlowKey returnKey;
    returnKey.src_ip = key.dst_ip;          // Server IP
    returnKey.dst_ip = external_ip;         // Firewall IP
    returnKey.dst_port = allocatedPort;     // Firewall Port/ID
    returnKey.protocol = key.protocol;

    // --- FIX FOR ICMP ---
    if (key.protocol == pcpp::ICMP) {
        // Dla ICMP, serwer odsyła ID, które otrzymał (czyli nasz allocatedPort).
        // Więc "Port Źródłowy" w pakiecie powrotnym to też allocatedPort.
        returnKey.src_port = allocatedPort;
    } else {
        // Dla TCP/UDP, port serwera się nie zmienia (np. 80, 443).
        returnKey.src_port = key.dst_port;
    }
    // --------------------

    table.createSession(returnKey, session);

    std::cout << "[NAT] Session Created: "
              << key.src_ip.toString() << ":" << key.src_port
              << " -> " << key.dst_ip.toString() << ":" << key.dst_port
              << " mapped to " << external_ip.toString() << ":" << allocatedPort << std::endl;

    return static_cast<NatSession*>(&storedRef);
}

void NatState::removeSession(const SessionFlowKey& key)
{
    table.eraseSession(key);
}