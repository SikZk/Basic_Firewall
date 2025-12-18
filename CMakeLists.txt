cmake_minimum_required(VERSION 3.16)
project(Basic_Firewall CXX)
set(CMAKE_CXX_STANDARD 20)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

add_executable(Basic_Firewall src/main.cpp
        include/policies/SecurityPolicy.h
        include/policies/NatPolicy.h
        include/security_profiles/UrlFilteringProfile.h
        include/security_profiles/AntimalwareProfile.h
        include/security_profiles/DlpProfile.h
        include/security_profiles/SecurityProfile.h
        include/decryption/DecryptionProfile.h
        include/session/sessions/Session.h
        include/routing/RoutingTable.h
        include/configuration/Config.h
        include/policies/Policy.h
        src/utils.cpp
        src/config/Config.cpp
        src/policies/Policy.cpp
        src/policies/SecurityPolicy.cpp
        src/policies/NatPolicy.cpp
        src/policies/NatService.cpp
        src/security_profiles/DlpProfile.cpp
        src/security_profiles/AntimalwareProfile.cpp
        src/security_profiles/UrlFilteringProfile.cpp
        src/security_profiles/SecurityProfile.cpp
        src/decryption/DecryptionProfile.cpp
        src/decryption/DecryptionManager.cpp
        src/routing/RoutingTable.cpp
        src/routing/RoutingEngine.cpp
        src/session/Session.cpp
        src/session/DecryptionSession.cpp
        src/session/NatSession.cpp
        src/session/session_tables/SessionTable.cpp
        src/session/session_tables/DecryptionSessionTable.cpp
        src/session/session_tables/NatSessionTable.cpp)

target_include_directories(Basic_Firewall PRIVATE
        /home/linuxbrew/.linuxbrew/Cellar/pcapplusplus/25.05/include
)
target_link_directories(Basic_Firewall PRIVATE
        /home/linuxbrew/.linuxbrew/Cellar/pcapplusplus/25.05/lib
)
target_link_libraries(Basic_Firewall PRIVATE
        Pcap++ Packet++ Common++ pcap pthread
        boost_json
        ssl crypto
)
