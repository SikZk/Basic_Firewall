#include "../../include/security_profiles/UrlFilteringProfile.h"
#include <iostream>
#include <algorithm>
#include <cctype>
#include <memory>
#include "pcapplusplus/TcpLayer.h"
#include "pcapplusplus/SSLLayer.h"
#include "pcapplusplus/SSLHandshake.h"
#include "pcapplusplus/HttpLayer.h"
#include "pcapplusplus/Packet.h"

UrlFilteringProfile::UrlFilteringProfile(const std::vector<std::string>& domains_to_block)
    : blocked_domains()
{
    for (const auto& domain : domains_to_block) {
        if (!domain.empty()) {
            blocked_domains.insert(normalizeHost(domain));
        }
    }
}

std::string UrlFilteringProfile::normalizeHost(std::string host)
{
    std::transform(host.begin(), host.end(), host.begin(), [](unsigned char ch) {
        return static_cast<char>(std::tolower(ch));
    });
    while (!host.empty() && host.back() == '.') {
        host.pop_back();
    }
    return host;
}

bool UrlFilteringProfile::shouldBlockHost(const std::string& host) const
{
    if (host.empty()) {
        return false;
    }
    std::string normalized = normalizeHost(host);

    if (blocked_domains.find(normalized) != blocked_domains.end()) {
        return true;
    }

    for (const auto& blocked : blocked_domains) {
        if (normalized.size() > blocked.size()) {
            size_t offset = normalized.size() - blocked.size();
            if (normalized[offset - 1] == '.' &&
                normalized.compare(offset, blocked.size(), blocked) == 0) {
                return true;
            }
        }
    }
    return false;
}

static std::string getSNIFromSSL(pcpp::SSLHandshakeLayer* handshakeLayer)
{
    if (!handshakeLayer) return {};

    auto* clientHello = handshakeLayer->getHandshakeMessageOfType<pcpp::SSLClientHelloMessage>();
    if (clientHello) {
        auto* sniExt = clientHello->getExtensionOfType<pcpp::SSLServerNameIndicationExtension>();
        if (sniExt) {
            return sniExt->getHostName();
        }
    }
    return {};
}

static std::string parseSSLFromPayload(const uint8_t* payload, size_t len)
{
    if (!payload || len == 0) return {};
    std::unique_ptr<uint8_t[]> dataCopy(new uint8_t[len]);
    std::memcpy(dataCopy.get(), payload, len);
    pcpp::SSLLayer* sslMsg = pcpp::SSLLayer::createSSLMessage(dataCopy.get(), len, nullptr, nullptr);

    if (!sslMsg) {
        return {};
    }
    dataCopy.release();
    std::unique_ptr<pcpp::SSLLayer> sslLayer(sslMsg);

    if (sslLayer->getRecordType() == pcpp::SSL_HANDSHAKE) {
        return getSNIFromSSL(dynamic_cast<pcpp::SSLHandshakeLayer*>(sslLayer.get()));
    }

    return {};
}

std::string UrlFilteringProfile::extractHostFromHttp(const std::string& payload)
{
    if (payload.empty()) return {};

    try {
        size_t len = payload.size();
        std::unique_ptr<uint8_t[]> dataCopy(new uint8_t[len]);
        std::memcpy(dataCopy.get(), payload.data(), len);

        pcpp::HttpRequestLayer requestLayer(dataCopy.get(), len, nullptr, nullptr);
        dataCopy.release();

        if (requestLayer.getFieldByName(PCPP_HTTP_HOST_FIELD)) {
            return requestLayer.getFieldByName(PCPP_HTTP_HOST_FIELD)->getFieldValue();
        }
    } catch (...) {
    }
    return {};
}

Action UrlFilteringProfile::scan(const DecryptionSession& session, const pcpp::IPv4Layer& ipv4_packet)
{
    std::string decrypted = session.getDecryptedDataAsString();
    std::string host = extractHostFromHttp(decrypted);

    if (host.empty()) {
        const auto* nextLayer = ipv4_packet.getNextLayer();
        const auto* tcpLayer = dynamic_cast<const pcpp::TcpLayer*>(nextLayer);

        if (tcpLayer) {
            const auto* possibleSsl = dynamic_cast<const pcpp::SSLHandshakeLayer*>(tcpLayer->getNextLayer());

            if (possibleSsl) {
                host = getSNIFromSSL(const_cast<pcpp::SSLHandshakeLayer*>(possibleSsl));
                if (!host.empty()) {
                    std::cout << "[DEBUG] SNI Found (Existing Layer): " << host << std::endl;
                }
            }
            if (host.empty()) {
                host = parseSSLFromPayload(tcpLayer->getLayerPayload(), tcpLayer->getLayerPayloadSize());
                if (!host.empty()) {
                    std::cout << "[DEBUG] SNI Found (Manual Parse): " << host << std::endl;
                }
            }
        }
    }

    if (shouldBlockHost(host)) {
        std::cout << "[UrlFiltering] Blocked (decrypted) host: " << host << std::endl;
        return BLOCK;
    }
    return ALLOW;
}

Action UrlFilteringProfile::scan(Session*, const pcpp::IPv4Layer& ipv4_packet)
{
    const auto* nextLayer = ipv4_packet.getNextLayer();
    const auto* tcpLayer = dynamic_cast<const pcpp::TcpLayer*>(nextLayer);

    if (!tcpLayer) {
        return ALLOW;
    }
    std::string host;

    const uint8_t* payload = tcpLayer->getLayerPayload();
    size_t payload_len = tcpLayer->getLayerPayloadSize();

    if (payload && payload_len > 0) {
        std::string payload_str(reinterpret_cast<const char*>(payload), payload_len);
        host = extractHostFromHttp(payload_str);
    }

    if (host.empty()) {
        const auto* possibleSsl = dynamic_cast<const pcpp::SSLHandshakeLayer*>(tcpLayer->getNextLayer());
        if (possibleSsl) {
             host = getSNIFromSSL(const_cast<pcpp::SSLHandshakeLayer*>(possibleSsl));
        }
        if (host.empty() && payload && payload_len > 0) {
             host = parseSSLFromPayload(payload, payload_len);
             if (!host.empty()) {
                 std::cout << "[DEBUG] SNI Found (No-Mitm, Manual): " << host << std::endl;
             }
        }
    }

    if (shouldBlockHost(host)) {
        std::cout << "[UrlFiltering] Blocked host: " << host << std::endl;
        return BLOCK;
    }
    return ALLOW;
}