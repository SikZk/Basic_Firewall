#include "../../include/decryption/DecryptionProfile.h"
#include <iostream>

DecryptionProfile::DecryptionProfile(std::string name,
                                     std::string ca_cert,
                                     std::string ca_key,
                                     std::string from_ip,
                                     uint32_t from_mask,
                                     std::string to_ip,
                                     uint32_t to_mask)
    : should_decrypt(false),
      profile_name(std::move(name)),
      ca_certificate_path(std::move(ca_cert)),
      ca_private_key_path(std::move(ca_key)),
      network_from(std::string(from_ip) + "/" + std::to_string(from_mask)),
      network_to(std::string(to_ip) + "/" + std::to_string(to_mask))
{
}

bool DecryptionProfile::loadCryptoMaterial()
{
    std::cout << "[DecryptionProfile] Skipping crypto material load (no-op)." << std::endl;
    return false;
}

bool DecryptionProfile::shouldDecrypt()
{
    return should_decrypt;
}

bool DecryptionProfile::doesMatchProfile(Session const& session) const
{
    (void)session;
    return false;
}

uint8_t* DecryptionProfile::decrypt()
{
    return nullptr;
}
