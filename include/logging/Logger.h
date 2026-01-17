#ifndef BASIC_FIREWALL_LOGGER_H
#define BASIC_FIREWALL_LOGGER_H

#include <mutex>
#include <string>

namespace firewall::logging {

class Logger {
public:
    static void info(const std::string& message);
    static void warn(const std::string& message);
    static void error(const std::string& message);

private:
    static void log(const char* level, const std::string& message);
    static std::mutex mutex_;
};

} // namespace firewall::logging

#endif // BASIC_FIREWALL_LOGGER_H
