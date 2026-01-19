#include "../../include/security_profiles/UrlFilteringProfile.h"
#include <iostream>
#include <algorithm>
#include <cctype>
#include "pcapplusplus/TcpLayer.h"

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
        if (normalized.size() > blocked.size() &&
            normalized.compare(normalized.size() - blocked.size(), blocked.size(), blocked) == 0 &&
            normalized[normalized.size() - blocked.size() - 1] == '.') {
            return true;
        }
    }
    return false;
}

std::string UrlFilteringProfile::extractHostFromHttp(const std::string& payload)
{
    if (payload.empty()) {
        return {};
    }
    std::string lower = payload;
    std::transform(lower.begin(), lower.end(), lower.begin(), [](unsigned char ch) {
        return static_cast<char>(std::tolower(ch));
    });

    const std::string host_header = "\r\nhost:";
    std::size_t host_pos = lower.find(host_header);
    if (host_pos == std::string::npos) {
        if (lower.rfind("host:", 0) == 0) {
            host_pos = 0;
        }
    } else {
        host_pos += 2; // skip CRLF
    }

    if (host_pos != std::string::npos) {
        std::size_t value_start = lower.find(':', host_pos);
        if (value_start != std::string::npos) {
            value_start++;
            while (value_start < payload.size() && std::isspace(static_cast<unsigned char>(payload[value_start]))) {
                value_start++;
            }
            std::size_t value_end = payload.find('\r', value_start);
            if (value_end != std::string::npos) {
                std::string host = payload.substr(value_start, value_end - value_start);
                std::size_t colon = host.find(':');
                if (colon != std::string::npos) {
                    host = host.substr(0, colon);
                }
                return host;
            }
        }
    }

    const std::string connect_prefix = "connect ";
    if (lower.rfind(connect_prefix, 0) == 0) {
        std::size_t start = connect_prefix.size();
        std::size_t end = lower.find(' ', start);
        if (end != std::string::npos) {
            std::string host = payload.substr(start, end - start);
            std::size_t colon = host.find(':');
            if (colon != std::string::npos) {
                host = host.substr(0, colon);
            }
            return host;
        }
    }

    const std::string http_prefix = "http://";
    const std::string https_prefix = "https://";
    std::size_t url_start = lower.find(http_prefix);
    if (url_start == std::string::npos) {
        url_start = lower.find(https_prefix);
    }
    if (url_start != std::string::npos) {
        url_start += (lower.compare(url_start, https_prefix.size(), https_prefix) == 0) ? https_prefix.size() : http_prefix.size();
        std::size_t url_end = lower.find('/', url_start);
        if (url_end == std::string::npos) {
            url_end = lower.find(' ', url_start);
        }
        if (url_end != std::string::npos && url_end > url_start) {
            std::string host = payload.substr(url_start, url_end - url_start);
            std::size_t colon = host.find(':');
            if (colon != std::string::npos) {
                host = host.substr(0, colon);
            }
            return host;
        }
    }

    return {};
}

std::string UrlFilteringProfile::extractHostFromTlsSni(const uint8_t* payload, size_t length)
{
    if (!payload || length < 5) {
        return {};
    }
    if (payload[0] != 0x16) { // Handshake
        return {};
    }
    size_t record_length = (static_cast<size_t>(payload[3]) << 8) | payload[4];
    size_t record_end = std::min(length, record_length + 5);
    if (record_end <= 5 || record_end > length) {
        record_end = length;
    }

    size_t pos = 5;
    if (pos + 4 > record_end || payload[pos] != 0x01) {
        return {};
    }
    size_t handshake_length = (static_cast<size_t>(payload[pos + 1]) << 16) |
                              (static_cast<size_t>(payload[pos + 2]) << 8) |
                              payload[pos + 3];
    pos += 4;
    size_t handshake_end = std::min(record_end, pos + handshake_length);
    if (pos + 2 + 32 > handshake_end) {
        return {};
    }
    pos += 2 + 32;

    if (pos >= handshake_end) {
        return {};
    }
    size_t session_id_len = payload[pos];
    pos += 1 + session_id_len;
    if (pos + 2 > handshake_end) {
        return {};
    }
    size_t cipher_suites_len = (static_cast<size_t>(payload[pos]) << 8) | payload[pos + 1];
    pos += 2 + cipher_suites_len;
    if (pos >= handshake_end) {
        return {};
    }
    size_t compression_len = payload[pos];
    pos += 1 + compression_len;
    if (pos + 2 > handshake_end) {
        return {};
    }
    size_t extensions_len = (static_cast<size_t>(payload[pos]) << 8) | payload[pos + 1];
    pos += 2;
    size_t extensions_end = std::min(handshake_end, pos + extensions_len);

    while (pos + 4 <= extensions_end) {
        uint16_t ext_type = (static_cast<uint16_t>(payload[pos]) << 8) | payload[pos + 1];
        uint16_t ext_len = (static_cast<uint16_t>(payload[pos + 2]) << 8) | payload[pos + 3];
        pos += 4;
        if (pos + ext_len > extensions_end) {
            break;
        }
        if (ext_type == 0x0000 && ext_len >= 2) {
            size_t list_len = (static_cast<size_t>(payload[pos]) << 8) | payload[pos + 1];
            size_t list_pos = pos + 2;
            size_t list_end = std::min(extensions_end, list_pos + list_len);
            while (list_pos + 3 <= list_end) {
                uint8_t name_type = payload[list_pos];
                uint16_t name_len = (static_cast<uint16_t>(payload[list_pos + 1]) << 8) | payload[list_pos + 2];
                list_pos += 3;
                if (list_pos + name_len > list_end) {
                    break;
                }
                if (name_type == 0x00 && name_len > 0) {
                    return std::string(reinterpret_cast<const char*>(payload + list_pos), name_len);
                }
                list_pos += name_len;
            }
        }
        pos += ext_len;
    }
    return {};
}

Action UrlFilteringProfile::scan(const DecryptionSession& session, pcpp::IPv4Layer ipv4_packet)
{
    std::string decrypted = session.getDecryptedDataAsString();
    std::string host = extractHostFromHttp(decrypted);
    if (host.empty()) {
        const auto* nextLayer = ipv4_packet.getNextLayer();
        auto* tcpLayer = dynamic_cast<const pcpp::TcpLayer*>(nextLayer);
        if (tcpLayer) {
            host = extractHostFromTlsSni(tcpLayer->getLayerPayload(), tcpLayer->getLayerPayloadSize());
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
    auto* tcpLayer = dynamic_cast<const pcpp::TcpLayer*>(nextLayer);
    if (!tcpLayer) {
        return ALLOW;
    }
    const uint8_t* payload = tcpLayer->getLayerPayload();
    size_t payload_len = tcpLayer->getLayerPayloadSize();
    if (!payload || payload_len == 0) {
        return ALLOW;
    }
    std::string payload_str(reinterpret_cast<const char*>(payload), payload_len);
    std::string host = extractHostFromHttp(payload_str);
    if (host.empty()) {
        host = extractHostFromTlsSni(payload, payload_len);
    }
    if (shouldBlockHost(host)) {
        std::cout << "[UrlFiltering] Blocked host: " << host << std::endl;
        return BLOCK;
    }
    return ALLOW;
}
