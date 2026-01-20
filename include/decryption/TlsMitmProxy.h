#pragma once

#include <atomic>
#include <mutex>
#include <string>
#include <thread>
#include <unordered_map>
#include <utility>

#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>

#include <openssl/ssl.h>
#include <functional>
#include <pcapplusplus/IpAddress.h>

#include "../configuration/Config.h"
class TlsMitmProxy {
    public:
    explicit TlsMitmProxy(Config& config);
    ~TlsMitmProxy();

    bool start();
    void stop();
    using DecryptedDataCallback = std::function<void(const pcpp::IPv4Address&, uint16_t,
                                                     const pcpp::IPv4Address&, uint16_t,
                                                     const uint8_t*, size_t)>;
    void setDecryptedServerDataCallback(DecryptedDataCallback callback);

private:
    Config& config;
    std::atomic<bool> running{false};
    DecryptedDataCallback on_server_decrypted;
    int listen_fd = -1;
    std::thread accept_thread;

    std::mutex cache_mutex;
    std::unordered_map<std::string, std::pair<X509*, EVP_PKEY*>> cert_cache;

    void acceptLoop();
    void handleClient(int client_fd, sockaddr_in client_addr);
    bool resolveOriginalDestination(int client_fd, sockaddr_in& destination) const;
    const DecryptionProfile* matchProfile(const pcpp::IPv4Address& source, const pcpp::IPv4Address& destination) const;
    std::pair<X509*, EVP_PKEY*> getOrCreateCertificate(const std::string& servername, const DecryptionProfile& profile);

    static int sniCallback(::SSL* ssl, int* alert, void* arg);

};
