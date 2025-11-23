//
// Created by mikolaj on 11/23/25.
//

#ifndef BASIC_FIREWALL_SECURITYPROFILE_H
#define BASIC_FIREWALL_SECURITYPROFILE_H

class SecurityProfile {
    enum Action {
        ALLOW,
        BLOCK,
        LOG_ONLY
    };

    virtual ~SecurityProfile() = default;

    virtual Action scan(const std::string& data_to_scan, uint64_t session_id) = 0;
};

#endif //BASIC_FIREWALL_SECURITYPROFILE_H