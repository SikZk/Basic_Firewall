cmake_minimum_required(VERSION 3.16)
project(Basic_Firewall CXX)
set(CMAKE_CXX_STANDARD 20)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

add_executable(Basic_Firewall src/main.cpp
        include/policies/SecurityPolicy.h
        include/policies/nat_policy.h
        include/security_profiles/url_filtering_profile.h
        include/security_profiles/antimalware_profile.h
        include/security_profiles/dlp_profile.h
        include/decryption/decryption_profile.h
        include/session/session.h
        include/session/session_table.h
        include/routing/routing_table.h
        include/configuration/configuration_parser.h
        include/configuration/config.h
        include/policies/Policy.h)

target_include_directories(Basic_Firewall PRIVATE
        /home/linuxbrew/.linuxbrew/Cellar/pcapplusplus/25.05/include
)
target_link_directories(Basic_Firewall PRIVATE
        /home/linuxbrew/.linuxbrew/Cellar/pcapplusplus/25.05/lib
)
target_link_libraries(Basic_Firewall PRIVATE
        Pcap++ Packet++ Common++ pcap pthread
)
