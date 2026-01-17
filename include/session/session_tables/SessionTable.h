//
// Created by mikolaj on 11/26/25.
//

#ifndef BASIC_FIREWALL_SESSIONTABLE_H
#define BASIC_FIREWALL_SESSIONTABLE_H
#include <boost/unordered/unordered_map_fwd.hpp>
#include <pcapplusplus/TcpLayer.h>
#include "../sessions/Session.h"

class SessionTable {
    public:
        using SessionMap = boost::unordered_map<SessionFlowKey, Session, SessionKeyHash, SessionKeyEq>;
    private:
        static SessionMap sessions_;

    public:
        SessionTable();
        Session* findSession(SessionFlowKey const& key);
        virtual Session& createSession(SessionFlowKey const& key, Session session);
        void eraseSession(SessionFlowKey const& key);
        bool isPacketEndingSession(const pcpp::TcpLayer& tcpLayer) const;
        bool doesSessionExist(const SessionFlowKey& key) const;
};

#endif //BASIC_FIREWALL_SESSIONTABLE_H
