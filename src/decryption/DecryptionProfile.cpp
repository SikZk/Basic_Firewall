#include <openssl/pem.h>
#include "../../include/decryption/DecryptionProfile.h"

DecryptionProfile::DecryptionProfile(
    std::string name,
    std::string ca_cert,
    std::string ca_key,
    std::string from_ip,
    uint32_t from_mask,
    std::string to_ip,
    uint32_t to_mask
)
    : should_decrypt(true)
    , profile_name(std::move(name))
    , ca_certificate_path(std::move(ca_cert))
    , ca_private_key_path(std::move(ca_key))
    , network_from(std::move(from_ip) + "/" + std::to_string(from_mask))
    , network_to(std::move(to_ip) + "/" + std::to_string(to_mask)) {}

bool DecryptionProfile::loadCryptoMaterial() {
    if (ca_cert != nullptr && ca_private_key != nullptr) return true;

    FILE* cert_file = fopen(ca_certificate_path.c_str(), "r");
    if (cert_file != nullptr) {
        ca_cert = PEM_read_X509(cert_file, nullptr, nullptr, nullptr);
        fclose(cert_file);
    }
    FILE* key_file = fopen(ca_private_key_path.c_str(), "r");
    if (key_file != nullptr) {
        ca_private_key = PEM_read_PrivateKey(key_file, nullptr, nullptr, nullptr);
        fclose(key_file);
    }
    return ca_cert != nullptr && ca_private_key != nullptr;
}

bool DecryptionProfile::shouldDecrypt() { return should_decrypt; }

bool DecryptionProfile::doesMatchProfile(Session const& session) const {
    (void)session;
    return true;
}

uint8_t* DecryptionProfile::decrypt() { return nullptr; }
