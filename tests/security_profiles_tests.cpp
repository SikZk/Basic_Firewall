#include "security_profiles/UrlFilteringProfile.h"
#include "security_profiles/AntimalwareProfile.h"
#include <iostream>
#include <stdexcept>
#include <string>
#include <vector>

class SecurityProfilesTest {
public:
    static void run()
    {
        testUrlNormalization();
        testUrlBlocking();
        testExtractHostFromHttp();
        testAntimalwareHashes();
        testExtractHttpResponseBody();
    }

private:
    static void assertTrue(bool condition, const std::string& message)
    {
        if (!condition) {
            throw std::runtime_error(message);
        }
    }

    static void assertEqual(const std::string& actual, const std::string& expected, const std::string& message)
    {
        if (actual != expected) {
            throw std::runtime_error(message + " (expected '" + expected + "' got '" + actual + "')");
        }
    }

    static void testUrlNormalization()
    {
        std::string normalized = UrlFilteringProfile::normalizeHost("Example.COM.");
        assertEqual(normalized, "example.com", "normalizeHost should lowercase and trim trailing dots");
    }

    static void testUrlBlocking()
    {
        UrlFilteringProfile profile({"example.com", "bad.site"});
        assertTrue(profile.shouldBlockHost("example.com"), "exact domain should be blocked");
        assertTrue(profile.shouldBlockHost("sub.example.com"), "subdomain should be blocked");
        assertTrue(profile.shouldBlockHost("bad.site."), "trailing dot should still be blocked");
        assertTrue(!profile.shouldBlockHost("notexample.com"), "unrelated domain should not be blocked");
    }

    static void testExtractHostFromHttp()
    {
        std::string payload = "GET /index.html HTTP/1.1\r\nHost: Example.com\r\n\r\n";
        std::string host = UrlFilteringProfile::extractHostFromHttp(payload);
        assertEqual(host, "Example.com", "extractHostFromHttp should parse the Host header");
    }

    static void testAntimalwareHashes()
    {
        std::string sample = "hello";
        std::vector<std::string> hashes = {"5d41402abc4b2a76b9719d911017c592"};
        AntimalwareProfile profile(hashes);

        std::string md5 = profile.calculateMD5(reinterpret_cast<const uint8_t*>(sample.data()), sample.size());
        std::string sha256 = profile.calculateSHA256(reinterpret_cast<const uint8_t*>(sample.data()), sample.size());

        assertEqual(md5, "5d41402abc4b2a76b9719d911017c592", "MD5 hash mismatch");
        assertEqual(sha256, "2cf24dba5fb0a30e26e83b2ac5b9e29e1b161e5c1fa7425e73043362938b9824", "SHA256 hash mismatch");
        assertTrue(profile.isKnownMalwareHash("5D41402ABC4B2A76B9719D911017C592"), "hash lookup should be case-insensitive");
    }

    static void testExtractHttpResponseBody()
    {
        AntimalwareProfile profile({});
        std::string buffer = "HTTP/1.1 200 OK\r\nContent-Length: 5\r\n\r\nhello";
        std::string body;
        size_t consumed = 0;
        bool extracted = profile.extractHttpResponseBody(buffer, body, consumed);
        assertTrue(extracted, "expected HTTP body to be extracted");
        assertEqual(body, "hello", "extracted body should match payload");
        assertTrue(consumed == buffer.size(), "consumed bytes should match full response length");

        std::string incomplete = "HTTP/1.1 200 OK\r\nContent-Length: 10\r\n\r\nhello";
        body.clear();
        consumed = 0;
        bool incompleteResult = profile.extractHttpResponseBody(incomplete, body, consumed);
        assertTrue(!incompleteResult, "incomplete responses should not be parsed");
    }
};

int main()
{
    try {
        SecurityProfilesTest::run();
    } catch (const std::exception& ex) {
        std::cerr << "Test failure: " << ex.what() << std::endl;
        return 1;
    }

    std::cout << "All tests passed." << std::endl;
    return 0;
}
