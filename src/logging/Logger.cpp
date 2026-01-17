#include "../../include/logging/Logger.h"

#include <chrono>
#include <ctime>
#include <iomanip>
#include <iostream>
#include <sstream>
#include <thread>

namespace firewall::logging {

std::mutex Logger::mutex_;

void Logger::info(const std::string& message)
{
    log("INFO", message);
}

void Logger::warn(const std::string& message)
{
    log("WARN", message);
}

void Logger::error(const std::string& message)
{
    log("ERROR", message);
}

void Logger::log(const char* level, const std::string& message)
{
    auto now = std::chrono::system_clock::now();
    std::time_t time = std::chrono::system_clock::to_time_t(now);
    std::tm tm{};
#ifdef _WIN32
    localtime_s(&tm, &time);
#else
    localtime_r(&time, &tm);
#endif

    std::ostringstream stream;
    stream << std::put_time(&tm, "%Y-%m-%d %H:%M:%S");
    stream << " [" << level << "]";
    stream << " [thread " << std::this_thread::get_id() << "] ";
    stream << message;

    std::lock_guard<std::mutex> lock(mutex_);
    std::cout << stream.str() << std::endl;
}

} // namespace firewall::logging
