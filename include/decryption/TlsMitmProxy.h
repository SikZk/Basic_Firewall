#pragma once

#include <atomic>
#include <functional>
#include <mutex>
#include <string>
#include <thread>
#include <unordered_map>
#include <utility>

#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>

#include <openssl/ssl.h>
#include <pcapplusplus/IpAddress.h>

#include "../configuration/Config.h"
/**
 * @brief TLS man-in-the-middle proxy for decrypting traffic.
 */
class TlsMitmProxy {
public:
    /**
     * @brief Construct a TLS MITM proxy.
     *
     * @param config Configuration containing MITM settings.
     */
    explicit TlsMitmProxy(Config& config);
    /**
     * @brief Destroy the proxy and release resources.
     */
    ~TlsMitmProxy();

    /**
     * @brief Start the proxy listener.
     *
     * @return True if the listener started successfully.
     */
    bool start();
    /**
     * @brief Stop the proxy listener.
     */
    void stop();

    /**
     * @brief Callback invoked with decrypted data.
     */
    using DecryptedDataCallback = std::function<void(const pcpp::IPv4Address&,
                                                     uint16_t,
                                                     const pcpp::IPv4Address&,
                                                     uint16_t,
                                                     const std::string&,
                                                     bool)>;
    /**
     * @brief Register a callback for decrypted payloads.
     *
     * @param callback Callback to invoke.
     */
    void setDecryptedDataCallback(DecryptedDataCallback callback);

private:
    Config& config;
    std::atomic<bool> running{false};
    int listen_fd = -1;
    std::thread accept_thread;

    std::mutex cache_mutex;
    std::unordered_map<std::string, std::pair<X509*, EVP_PKEY*>> cert_cache;
    DecryptedDataCallback decrypted_data_callback;

    /**
     * @brief Accept incoming client connections.
     */
    void acceptLoop();
    /**
     * @brief Handle a single client connection.
     *
     * @param client_fd Client socket descriptor.
     * @param client_addr Client address information.
     */
    void handleClient(int client_fd, sockaddr_in client_addr);
    /**
     * @brief Resolve original destination for a redirected connection.
     *
     * @param client_fd Client socket descriptor.
     * @param destination Output destination address.
     * @return True if destination was resolved.
     */
    bool resolveOriginalDestination(int client_fd, sockaddr_in& destination) const;
    /**
     * @brief Match a decryption profile for endpoints.
     *
     * @param source Source IP address.
     * @param destination Destination IP address.
     * @return Pointer to matching profile or nullptr.
     */
    const DecryptionProfile* matchProfile(const pcpp::IPv4Address& source, const pcpp::IPv4Address& destination) const;
    /**
     * @brief Retrieve or create a forged certificate for a server.
     *
     * @param servername Server name for certificate generation.
     * @param profile Decryption profile providing CA material.
     * @return Certificate/key pair for the server.
     */
    std::pair<X509*, EVP_PKEY*> getOrCreateCertificate(const std::string& servername, const DecryptionProfile& profile);

    /**
     * @brief OpenSSL SNI callback for dynamic certificate selection.
     *
     * @param ssl SSL connection.
     * @param alert Alert output parameter.
     * @param arg Callback context.
     * @return OpenSSL callback result code.
     */
    static int sniCallback(::SSL* ssl, int* alert, void* arg);

};
