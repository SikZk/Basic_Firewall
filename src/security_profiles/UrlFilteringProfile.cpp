#include "../../include/security_profiles/UrlFilteringProfile.h"
#include <iostream>
#include <algorithm>
#include <netinet/in.h>
#include <pcapplusplus/TcpLayer.h>
#include <pcapplusplus/Packet.h>
#include <pcapplusplus/HttpLayer.h>
#include <pcapplusplus/SSLLayer.h>
#include <pcapplusplus/SSLHandshake.h>

UrlFilteringProfile::UrlFilteringProfile(std::string name, const std::vector<std::string>& domains_to_block)
    : name(std::move(name)), blocked_domains(domains_to_block.begin(), domains_to_block.end())
{
}

Action UrlFilteringProfile::scan(const DecryptionSession&, const pcpp::Packet&)
{
    // This overload seems to be for decrypted traffic (not yet fully implemented context).
    // For now, we'll assume this is a placeholder or handle it if we have the decrypted packet.
    // If we receive a decrypted HTTP packet here, we should scan it like HTTP.
    std::cout << "[UrlFiltering] Scan called for DecryptionSession (not fully implemented)." << std::endl;
    return ALLOW;
}

Action UrlFilteringProfile::scan(Session*, const pcpp::Packet& packet)
{
    // 1. Check if it carries TCP
    pcpp::TcpLayer* tcpLayer = packet.getLayerOfType<pcpp::TcpLayer>();
    if (!tcpLayer) return ALLOW;

    uint16_t dstPort = ntohs(tcpLayer->getTcpHeader()->portDst);

    // 2. HTTP Filtering (Port 80)
    if (dstPort == 80) {
        pcpp::HttpRequestLayer* httpRequest = packet.getLayerOfType<pcpp::HttpRequestLayer>();
        if (httpRequest) {
            pcpp::HeaderField* hostField = httpRequest->getFieldByName(PCPP_HTTP_HOST_FIELD);
            if (hostField) {
                std::string host = hostField->getFieldValue();
                // Simple exact match or subsequence check?
                // For now, let's do direct lookup for exact matches or simple substring if needed.
                // The requirement says "based on url... in simple http by simple url"
                // Usually blocked_domains are "example.com".
                
                // Let's check if the host is in blocked_domains
                if (blocked_domains.find(host) != blocked_domains.end()) {
                    std::cout << "[UrlFiltering] BLOCKING HTTP Host: " << host << std::endl;
                    return BLOCK;
                }
            }
            // Logic for full URL filtering could be added here (e.g. checking path) but usually Host is the main one for "domain" blocking.
        }
    }

    // 3. HTTPS SNI Filtering (Port 443) - Client Hello
    if (dstPort == 443) {
        pcpp::SSLHandshakeLayer* sslHandshakeLayer = packet.getLayerOfType<pcpp::SSLHandshakeLayer>();
        if (sslHandshakeLayer) {
            pcpp::SSLClientHelloMessage* clientHello = sslHandshakeLayer->getHandshakeMessageOfType<pcpp::SSLClientHelloMessage>();
            if (clientHello) {
                pcpp::SSLServerNameIndicationExtension* sniExt = clientHello->getExtensionOfType<pcpp::SSLServerNameIndicationExtension>();
                if (sniExt) {
                    std::string hostname = sniExt->getHostName();
                    if (blocked_domains.find(hostname) != blocked_domains.end()) {
                        std::cout << "[UrlFiltering] BLOCKING HTTPS SNI: " << hostname << std::endl;
                        return BLOCK;
                    }
                }
            }
        }
    }

    return ALLOW;
}
