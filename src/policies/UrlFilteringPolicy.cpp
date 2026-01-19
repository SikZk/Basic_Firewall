#include "../../include/policies/UrlFilteringPolicy.h"
#include <algorithm>
#include <cctype>
#include <sstream>

UrlFilteringPolicy::UrlFilteringPolicy(
    std::string network_from_str,
    uint32_t network_from_mask,
    std::string network_to_str,
    uint32_t network_to_mask,
    uint16_t source_port,
    uint16_t destination_port,
    std::vector<std::string> blocked_urls
)
    : Policy(
        std::move(network_from_str),
        network_from_mask,
        std::move(network_to_str),
        network_to_mask,
        source_port,
        destination_port
    )
{
    block_rules.reserve(blocked_urls.size());
    for (const auto& entry : blocked_urls) {
        const auto trimmed = trimCopy(entry);
        if (trimmed.empty()) {
            continue;
        }
        const auto lowered = toLowerCopy(stripScheme(trimmed));
        std::string host;
        std::string path;
        auto slash = lowered.find('/');
        if (slash == std::string::npos) {
            host = lowered;
        } else {
            host = lowered.substr(0, slash);
            path = lowered.substr(slash);
        }
        host = stripPort(trimCopy(host));
        if (host.empty()) {
            continue;
        }
        BlockRule rule{
            normalizeHost(host),
            normalizePath(path),
            !path.empty()
        };
        block_rules.push_back(std::move(rule));
    }
}

bool UrlFilteringPolicy::isBlockedHost(const std::string& host) const
{
    const auto normalized = normalizeHost(host);
    if (normalized.empty()) {
        return false;
    }
    for (const auto& rule : block_rules) {
        if (matchesHostRule(normalized, rule)) {
            if (!rule.has_path) {
                return true;
            }
        }
    }
    return false;
}

bool UrlFilteringPolicy::isBlockedUrl(const std::string& host, const std::string& path) const
{
    const auto normalizedHost = normalizeHost(host);
    if (normalizedHost.empty()) {
        return false;
    }
    const auto normalizedPath = normalizePath(path);
    for (const auto& rule : block_rules) {
        if (!matchesHostRule(normalizedHost, rule)) {
            continue;
        }
        if (!rule.has_path) {
            return true;
        }
        if (!normalizedPath.empty() && normalizedPath.rfind(rule.path, 0) == 0) {
            return true;
        }
    }
    return false;
}

bool UrlFilteringPolicy::isBlockedFullUrl(const std::string& url) const
{
    const auto cleaned = toLowerCopy(stripScheme(trimCopy(url)));
    auto slash = cleaned.find('/');
    std::string host = slash == std::string::npos ? cleaned : cleaned.substr(0, slash);
    std::string path = slash == std::string::npos ? "" : cleaned.substr(slash);
    host = stripPort(trimCopy(host));
    if (host.empty()) {
        return false;
    }
    return isBlockedUrl(host, path);
}

std::string UrlFilteringPolicy::normalizeHost(const std::string& host)
{
    auto normalized = toLowerCopy(trimCopy(stripPort(host)));
    normalized.erase(0, normalized.find_first_not_of('.'));
    while (!normalized.empty() && normalized.back() == '.') {
        normalized.pop_back();
    }
    return normalized;
}

std::string UrlFilteringPolicy::normalizePath(const std::string& path)
{
    if (path.empty()) {
        return "";
    }
    std::string normalized = trimCopy(path);
    if (normalized.empty()) {
        return "";
    }
    if (normalized.front() != '/') {
        normalized.insert(normalized.begin(), '/');
    }
    return normalized;
}

std::string UrlFilteringPolicy::stripScheme(const std::string& value)
{
    auto pos = value.find("://");
    if (pos == std::string::npos) {
        return value;
    }
    return value.substr(pos + 3);
}

std::string UrlFilteringPolicy::stripPort(const std::string& host)
{
    auto pos = host.find(':');
    if (pos == std::string::npos) {
        return host;
    }
    return host.substr(0, pos);
}

std::string UrlFilteringPolicy::toLowerCopy(const std::string& value)
{
    std::string lowered = value;
    std::transform(lowered.begin(), lowered.end(), lowered.begin(), [](unsigned char ch) {
        return static_cast<char>(std::tolower(ch));
    });
    return lowered;
}

std::string UrlFilteringPolicy::trimCopy(const std::string& value)
{
    auto start = value.find_first_not_of(" \t\r\n");
    if (start == std::string::npos) {
        return "";
    }
    auto end = value.find_last_not_of(" \t\r\n");
    return value.substr(start, end - start + 1);
}

bool UrlFilteringPolicy::matchesHostRule(const std::string& host, const BlockRule& rule) const
{
    if (rule.host == host) {
        return true;
    }
    if (host.size() > rule.host.size() &&
        host.compare(host.size() - rule.host.size(), rule.host.size(), rule.host) == 0) {
        return host[host.size() - rule.host.size() - 1] == '.';
    }
    return false;
}
