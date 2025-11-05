//
// Created by mikolaj on 11/5/25.
//

#ifndef BASIC_FIREWALL_SECURITY_POLICY_H
#define BASIC_FIREWALL_SECURITY_POLICY_H
#include <pcapplusplus/IpAddress.h>
#include <pcapplusplus/IPv4Layer.h>

#include "Policy.h"

class SecurityPolicy {
    enum class Action {
        Deny, Allow
    };

    private:
        Policy policy;
        Action action{Action::Deny};

    public:
        bool pass_security_policy(pcpp::IPv4Layer ipv4_packet);

};

#endif //BASIC_FIREWALL_SECURITY_POLICY_H