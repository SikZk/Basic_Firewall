#include "../../include/decryption/TlsMitmProxy.h"

#include <arpa/inet.h>
#include <netinet/in.h>
#include <sys/select.h>
#include <sys/socket.h>
#include <unistd.h>

#include <chrono>
#include <cstdlib>
#include <algorithm>
#include <iostream>
#include <vector>

#include <openssl/err.h>
#include <openssl/pem.h>
#include <openssl/rsa.h>
#include <openssl/x509v3.h>

#ifdef __linux__
#include <linux/netfilter_ipv4.h>
#endif

namespace {

EVP_PKEY* generateKey()
{
    EVP_PKEY* pkey = EVP_PKEY_new();
    if (!pkey) return nullptr;

    RSA* rsa = RSA_new();
    BIGNUM* e = BN_new();
    if (!rsa || !e) {
        EVP_PKEY_free(pkey);
        RSA_free(rsa);
        BN_free(e);
        return nullptr;
    }
    BN_set_word(e, RSA_F4);
    if (RSA_generate_key_ex(rsa, 2048, e, nullptr) != 1) {
        EVP_PKEY_free(pkey);
        RSA_free(rsa);
        BN_free(e);
        return nullptr;
    }
    BN_free(e);
    if (EVP_PKEY_assign_RSA(pkey, rsa) != 1) {
        EVP_PKEY_free(pkey);
        RSA_free(rsa);
        return nullptr;
    }
    return pkey;
}

X509* createCertificate(const std::string& servername, X509* ca_cert, EVP_PKEY* ca_key, EVP_PKEY* leaf_key)
{
    X509* cert = X509_new();
    if (!cert) return nullptr;

    ASN1_INTEGER_set(X509_get_serialNumber(cert), std::rand());
    X509_gmtime_adj(X509_get_notBefore(cert), 0);
    X509_gmtime_adj(X509_get_notAfter(cert), 60L * 60L * 24L * 365L);

    X509_set_pubkey(cert, leaf_key);

    X509_NAME* name = X509_NAME_new();
    X509_NAME_add_entry_by_txt(name, "CN", MBSTRING_ASC,
                               reinterpret_cast<const unsigned char*>(servername.c_str()),
                               -1, -1, 0);
    X509_set_subject_name(cert, name);
    X509_NAME_free(name);

    X509_set_issuer_name(cert, X509_get_subject_name(ca_cert));

    X509V3_CTX ctx;
    X509V3_set_ctx(&ctx, ca_cert, cert, nullptr, nullptr, 0);
    std::string san = "DNS:" + servername;
    X509_EXTENSION* ext = X509V3_EXT_conf_nid(nullptr, &ctx, NID_subject_alt_name, san.c_str());
    if (ext) {
        X509_add_ext(cert, ext, -1);
        X509_EXTENSION_free(ext);
    }

    if (X509_sign(cert, ca_key, EVP_sha256()) == 0) {
        X509_free(cert);
        return nullptr;
    }
    return cert;
}

void tunnelBytes(int client_fd, int server_fd)
{
    std::vector<uint8_t> buffer(16 * 1024);
    while (true) {
        fd_set readfds;
        FD_ZERO(&readfds);
        FD_SET(client_fd, &readfds);
        FD_SET(server_fd, &readfds);
        int maxfd = std::max(client_fd, server_fd);
        if (select(maxfd + 1, &readfds, nullptr, nullptr, nullptr) <= 0) {
            break;
        }
        if (FD_ISSET(client_fd, &readfds)) {
            ssize_t n = recv(client_fd, buffer.data(), buffer.size(), 0);
            if (n <= 0) break;
            if (send(server_fd, buffer.data(), static_cast<size_t>(n), 0) <= 0) break;
        }
        if (FD_ISSET(server_fd, &readfds)) {
            ssize_t n = recv(server_fd, buffer.data(), buffer.size(), 0);
            if (n <= 0) break;
            if (send(client_fd, buffer.data(), static_cast<size_t>(n), 0) <= 0) break;
        }
    }
}

}

TlsMitmProxy::TlsMitmProxy(Config& config)
    : config(config)
{
    SSL_library_init();
    SSL_load_error_strings();
    OpenSSL_add_all_algorithms();
}

TlsMitmProxy::~TlsMitmProxy()
{
    stop();
}

void TlsMitmProxy::setDecryptedDataCallback(DecryptedDataCallback callback)
{
    decrypted_data_callback = std::move(callback);
}

bool TlsMitmProxy::start()
{
    if (running.load()) return true;

    listen_fd = socket(AF_INET, SOCK_STREAM, 0);
    if (listen_fd < 0) {
        std::cerr << "[TLS MITM] Failed to create listen socket." << std::endl;
        return false;
    }

    int reuse = 1;
    setsockopt(listen_fd, SOL_SOCKET, SO_REUSEADDR, &reuse, sizeof(reuse));

    sockaddr_in addr{};
    addr.sin_family = AF_INET;
    addr.sin_addr.s_addr = INADDR_ANY;
    addr.sin_port = htons(config.tls_mitm_port);

    if (bind(listen_fd, reinterpret_cast<sockaddr*>(&addr), sizeof(addr)) < 0) {
        std::cerr << "[TLS MITM] Failed to bind port " << config.tls_mitm_port << std::endl;
        close(listen_fd);
        listen_fd = -1;
        return false;
    }

    if (listen(listen_fd, 64) < 0) {
        std::cerr << "[TLS MITM] Failed to listen on port " << config.tls_mitm_port << std::endl;
        close(listen_fd);
        listen_fd = -1;
        return false;
    }

    running = true;
    accept_thread = std::thread(&TlsMitmProxy::acceptLoop, this);
    std::cout << "[TLS MITM] Listening on port " << config.tls_mitm_port << std::endl;
    return true;
}

void TlsMitmProxy::stop()
{
    if (!running.exchange(false)) {
        return;
    }
    if (listen_fd >= 0) {
        close(listen_fd);
        listen_fd = -1;
    }
    if (accept_thread.joinable()) {
        accept_thread.join();
    }

    std::lock_guard<std::mutex> lock(cache_mutex);
    for (auto& [_, pair] : cert_cache) {
        if (pair.first) X509_free(pair.first);
        if (pair.second) EVP_PKEY_free(pair.second);
    }
    cert_cache.clear();
}

void TlsMitmProxy::acceptLoop()
{
    while (running.load()) {
        sockaddr_in client_addr{};
        socklen_t len = sizeof(client_addr);
        int client_fd = accept(listen_fd, reinterpret_cast<sockaddr*>(&client_addr), &len);
        if (client_fd < 0) {
            if (running.load()) {
                std::this_thread::sleep_for(std::chrono::milliseconds(10));
            }
            continue;
        }
        std::thread(&TlsMitmProxy::handleClient, this, client_fd, client_addr).detach();
    }
}

bool TlsMitmProxy::resolveOriginalDestination(int client_fd, sockaddr_in& destination) const
{
#ifdef __linux__
    socklen_t len = sizeof(destination);
    if (getsockopt(client_fd, SOL_IP, SO_ORIGINAL_DST, &destination, &len) == 0) {
        return true;
    }
#endif
    (void)client_fd;
    return false;
}

const DecryptionProfile* TlsMitmProxy::matchProfile(const pcpp::IPv4Address& source,
                                                    const pcpp::IPv4Address& destination) const
{
    for (const auto& profile : config.decryption_profiles) {
        if (!profile.shouldDecrypt()) {
            continue;
        }
        if (profile.matchesEndpoints(source, destination)) {
            return &profile;
        }
    }
    return nullptr;
}

std::pair<X509*, EVP_PKEY*> TlsMitmProxy::getOrCreateCertificate(const std::string& servername,
                                                                 const DecryptionProfile& profile)
{
    std::lock_guard<std::mutex> lock(cache_mutex);
    if (auto it = cert_cache.find(servername); it != cert_cache.end()) {
        return it->second;
    }

    EVP_PKEY* leaf_key = generateKey();
    if (!leaf_key) {
        return {nullptr, nullptr};
    }
    X509* leaf_cert = createCertificate(servername, profile.getCaCert(), profile.getCaPrivateKey(), leaf_key);
    if (!leaf_cert) {
        EVP_PKEY_free(leaf_key);
        return {nullptr, nullptr};
    }
    cert_cache.emplace(servername, std::make_pair(leaf_cert, leaf_key));
    return {leaf_cert, leaf_key};
}

int TlsMitmProxy::sniCallback(::SSL* ssl, int* alert, void* arg) {

    auto* proxy = static_cast<TlsMitmProxy*>(arg);
    const char* servername = SSL_get_servername(ssl, TLSEXT_NAMETYPE_host_name);
    if (!servername || !proxy) {
        return SSL_TLSEXT_ERR_NOACK;
    }
    auto* profile = static_cast<const DecryptionProfile*>(SSL_get_app_data(ssl));
    if (!profile || !profile->getCaCert() || !profile->getCaPrivateKey()) {
        return SSL_TLSEXT_ERR_NOACK;
    }
    auto [cert, key] = proxy->getOrCreateCertificate(servername, *profile);
    if (!cert || !key) {
        return SSL_TLSEXT_ERR_ALERT_FATAL;
    }
    SSL_use_certificate(ssl, cert);
    SSL_use_PrivateKey(ssl, key);
    return SSL_TLSEXT_ERR_OK;
}

void TlsMitmProxy::handleClient(int client_fd, sockaddr_in client_addr)
{
    sockaddr_in dst_addr{};
    if (!resolveOriginalDestination(client_fd, dst_addr)) {
        std::cerr << "[TLS MITM] Unable to resolve original destination, closing connection." << std::endl;
        close(client_fd);
        return;
    }

    pcpp::IPv4Address src_ip(inet_ntoa(client_addr.sin_addr));
    uint16_t src_port = ntohs(client_addr.sin_port);
    pcpp::IPv4Address dst_ip(inet_ntoa(dst_addr.sin_addr));
    uint16_t dst_port = ntohs(dst_addr.sin_port);

    const DecryptionProfile* profile = matchProfile(src_ip, dst_ip);
    if (!profile || !profile->getCaCert() || !profile->getCaPrivateKey()) {
        int server_fd = socket(AF_INET, SOCK_STREAM, 0);
        if (server_fd < 0) {
            close(client_fd);
            return;
        }
        if (connect(server_fd, reinterpret_cast<sockaddr*>(&dst_addr), sizeof(dst_addr)) < 0) {
            close(server_fd);
            close(client_fd);
            return;
        }
        tunnelBytes(client_fd, server_fd);
        close(server_fd);
        close(client_fd);
        return;
    }

    SSL_CTX* server_ctx = SSL_CTX_new(TLS_server_method());
    SSL_CTX_set_tlsext_servername_callback(server_ctx, &TlsMitmProxy::sniCallback);
    SSL_CTX_set_tlsext_servername_arg(server_ctx, this);

    SSL* client_ssl = SSL_new(server_ctx);
    SSL_set_fd(client_ssl, client_fd);
    SSL_set_app_data(client_ssl, const_cast<DecryptionProfile*>(profile));

    if (SSL_accept(client_ssl) <= 0) {
        SSL_free(client_ssl);
        SSL_CTX_free(server_ctx);
        close(client_fd);
        return;
    }

    std::string servername;
    if (const char* sni = SSL_get_servername(client_ssl, TLSEXT_NAMETYPE_host_name)) {
        servername = sni;
    } else {
        servername = dst_ip.toString();
    }

    int server_fd = socket(AF_INET, SOCK_STREAM, 0);
    if (server_fd < 0) {
        SSL_free(client_ssl);
        SSL_CTX_free(server_ctx);
        close(client_fd);
        return;
    }
    if (connect(server_fd, reinterpret_cast<sockaddr*>(&dst_addr), sizeof(dst_addr)) < 0) {
        close(server_fd);
        SSL_free(client_ssl);
        SSL_CTX_free(server_ctx);
        close(client_fd);
        return;
    }

    SSL_CTX* client_ctx = SSL_CTX_new(TLS_client_method());
    SSL* server_ssl = SSL_new(client_ctx);
    SSL_set_fd(server_ssl, server_fd);
    SSL_set_tlsext_host_name(server_ssl, servername.c_str());
    if (SSL_connect(server_ssl) <= 0) {
        SSL_free(server_ssl);
        SSL_CTX_free(client_ctx);
        close(server_fd);
        SSL_free(client_ssl);
        SSL_CTX_free(server_ctx);
        close(client_fd);
        return;
    }

    std::cout << "[TLS MITM] Decrypting HTTPS traffic for " << servername << " from "
              << src_ip.toString() << " to " << dst_ip.toString() << ":" << dst_port << std::endl;

    std::vector<char> buffer(16 * 1024);
    int client_fd_raw = SSL_get_fd(client_ssl);
    int server_fd_raw = SSL_get_fd(server_ssl);

    bool active = true;
    while (active) {
        fd_set readfds;
        FD_ZERO(&readfds);
        FD_SET(client_fd_raw, &readfds);
        FD_SET(server_fd_raw, &readfds);
        int maxfd = std::max(client_fd_raw, server_fd_raw);
        if (select(maxfd + 1, &readfds, nullptr, nullptr, nullptr) <= 0) {
            break;
        }

        if (FD_ISSET(client_fd_raw, &readfds)) {
            int n = SSL_read(client_ssl, buffer.data(), static_cast<int>(buffer.size()));
            if (n <= 0) {
                active = false;
            } else {
                if (decrypted_data_callback) {
                    decrypted_data_callback(src_ip, src_port, dst_ip, dst_port,
                                            std::string(buffer.data(), buffer.data() + n), true);
                }
                std::cout << "[TLS MITM] Client -> Server (" << servername << ") [" << n
                          << " bytes]: " << std::string(buffer.data(), buffer.data() + n) << std::endl;
                if (SSL_write(server_ssl, buffer.data(), n) <= 0) {
                    active = false;
                }
            }
        }

        if (FD_ISSET(server_fd_raw, &readfds)) {
            int n = SSL_read(server_ssl, buffer.data(), static_cast<int>(buffer.size()));
            if (n <= 0) {
                active = false;
            } else {
                if (decrypted_data_callback) {
                    decrypted_data_callback(dst_ip, dst_port, src_ip, src_port,
                                            std::string(buffer.data(), buffer.data() + n), false);
                }
                std::cout << "[TLS MITM] Server -> Client (" << servername << ") [" << n
                          << " bytes]: " << std::string(buffer.data(), buffer.data() + n) << std::endl;
                if (SSL_write(client_ssl, buffer.data(), n) <= 0) {
                    active = false;
                }
            }
        }
    }

    SSL_shutdown(server_ssl);
    SSL_free(server_ssl);
    SSL_CTX_free(client_ctx);
    close(server_fd);

    SSL_shutdown(client_ssl);
    SSL_free(client_ssl);
    SSL_CTX_free(server_ctx);
    close(client_fd);
    std::cout << "[TLS MITM] Connection closed for " << servername << " (" << dst_ip.toString()
              << ":" << dst_port << ")" << std::endl;
}
