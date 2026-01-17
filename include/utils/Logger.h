#ifndef BASIC_FIREWALL_LOGGER_H
#define BASIC_FIREWALL_LOGGER_H

#include <iostream>
#include <mutex>
#include <string>
#include <thread>

namespace Logging {

inline void logLine(const std::string& tag, const std::string& message)
{
    static std::mutex log_mutex;
    std::lock_guard<std::mutex> lock(log_mutex);
    std::cout << tag << " [tid " << std::this_thread::get_id() << "] " << message << std::endl;
}

} // namespace Logging

#endif
