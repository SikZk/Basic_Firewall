#include "../../include/logging/Logger.h"

#include <chrono>
#include <ctime>
#include <iomanip>
#include <sstream>
#include <thread>
#include <fstream>
#include <iostream>
#include <stdexcept>

namespace firewall::logging {

    std::mutex Logger::mutex_;

    // Default log file path (change as you like)
    static const char* kDefaultLogPath = "firewall.log";

    // A single shared output stream for the process.
    static std::ofstream& logStream()
    {
        static std::ofstream out(kDefaultLogPath, std::ios::out | std::ios::app);
        // If the file can't be opened, you can either throw, or fallback to stderr.
        // Throwing in logging is sometimes undesirable; see alternative below.
        return out;
    }

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

        std::ofstream& out = logStream();
        if (out.is_open() && out.good()) {
            out << stream.str() << '\n';
            out.flush(); // remove if you want higher performance with less immediate durability
        } else {
            // Fallback if file can't be opened (optional)
            std::cerr << stream.str() << std::endl;
        }
    }

} // namespace firewall::logging
