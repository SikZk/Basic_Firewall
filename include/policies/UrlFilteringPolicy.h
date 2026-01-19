#pragma once

#include "Policy.h"
#include <string>
#include <vector>

class UrlFilteringPolicy : public Policy {
public:
    struct BlockRule {
        std::string host;
        std::string path;
        bool has_path;
    };

    UrlFilteringPolicy(
        std::string network_from_str,
        uint32_t network_from_mask,
        std::string network_to_str,
        uint32_t network_to_mask,
        uint16_t source_port,
        uint16_t destination_port,
        std::vector<std::string> blocked_urls
    );

    bool isBlockedHost(const std::string& host) const;
    bool isBlockedUrl(const std::string& host, const std::string& path) const;
    bool isBlockedFullUrl(const std::string& url) const;

private:
    std::vector<BlockRule> block_rules;

    static std::string normalizeHost(const std::string& host);
    static std::string normalizePath(const std::string& path);
    static std::string stripScheme(const std::string& value);
    static std::string stripPort(const std::string& host);
    static std::string toLowerCopy(const std::string& value);
    static std::string trimCopy(const std::string& value);
    bool matchesHostRule(const std::string& host, const BlockRule& rule) const;
};
