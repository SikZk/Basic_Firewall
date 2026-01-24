cmake_minimum_required(VERSION 3.16)
project(Basic_Firewall)
set(CMAKE_CXX_STANDARD 20)
set(CMAKE_EXPORT_COMPILE_COMMANDS ON)
find_package(OpenSSL REQUIRED)

add_executable(Basic_Firewall src/main.cpp
        include/policies/SecurityPolicy.h
        include/policies/NatPolicy.h
        include/security_profiles/UrlFilteringProfile.h
        include/security_profiles/AntimalwareProfile.h
        include/security_profiles/DlpProfile.h
        include/decryption/DecryptionProfile.h
        include/session/sessions/Session.h
        include/routing/RoutingTable.h
        include/configuration/Config.h
        include/policies/Policy.h
        src/utils.cpp
        src/configuration/Config.cpp
        src/session/sessions/Session.cpp
        src/decryption/DecryptionManager.cpp
        src/decryption/DecryptionProfile.cpp
        src/decryption/TlsMitmProxy.cpp
        src/session/sessions/DecryptionSession.cpp
        src/session/sessions/NatSession.cpp
        src/session/session_tables/SessionTable.cpp
        src/session/session_tables/DecryptionSessionTable.cpp
        src/session/session_tables/NatSessionTable.cpp
        src/policies/Policy.cpp
        src/policies/SecurityPolicy.cpp
        src/policies/NatPolicy.cpp
        src/policies/NatService.cpp
        src/routing/RoutingTable.cpp
        src/routing/RoutingEngine.cpp
        src/security_profiles/SecurityProfile.cpp
        src/security_profiles/UrlFilteringProfile.cpp
        src/security_profiles/AntimalwareProfile.cpp
        src/security_profiles/DlpProfile.cpp
)
target_link_libraries(Basic_Firewall
        PRIVATE
        OpenSSL::Crypto
        OpenSSL::SSL
)
set(PCAPPLUSPLUS_ROOT /home/linuxbrew/.linuxbrew/opt/pcapplusplus)
target_include_directories(Basic_Firewall PRIVATE
        ${PCAPPLUSPLUS_ROOT}/include
)
target_link_directories(Basic_Firewall PRIVATE
        ${PCAPPLUSPLUS_ROOT}/lib
)
target_link_libraries(Basic_Firewall PRIVATE
        Pcap++ Packet++ Common++ pcap pthread ssl crypto
)

enable_testing()

add_executable(Basic_Firewall_Tests
        tests/security_profiles_tests.cpp
        src/security_profiles/SecurityProfile.cpp
        src/security_profiles/UrlFilteringProfile.cpp
        src/security_profiles/AntimalwareProfile.cpp
        src/session/sessions/Session.cpp
        src/session/sessions/DecryptionSession.cpp
)
target_include_directories(Basic_Firewall_Tests PRIVATE
        include
        ${PCAPPLUSPLUS_ROOT}/include
)
target_link_directories(Basic_Firewall_Tests PRIVATE
        ${PCAPPLUSPLUS_ROOT}/lib
)
target_link_libraries(Basic_Firewall_Tests PRIVATE
        OpenSSL::Crypto
        OpenSSL::SSL
        Pcap++ Packet++ Common++ pcap pthread ssl crypto
)

add_test(NAME Basic_Firewall_Tests COMMAND Basic_Firewall_Tests)

get_target_property(BASIC_FIREWALL_SOURCES Basic_Firewall SOURCES)
get_target_property(BASIC_FIREWALL_TEST_SOURCES Basic_Firewall_Tests SOURCES)
set(BASIC_FIREWALL_LINT_SOURCES ${BASIC_FIREWALL_SOURCES} ${BASIC_FIREWALL_TEST_SOURCES})
list(REMOVE_DUPLICATES BASIC_FIREWALL_LINT_SOURCES)
add_custom_target(lint
        COMMAND clang-tidy -p ${CMAKE_BINARY_DIR} ${BASIC_FIREWALL_LINT_SOURCES}
        WORKING_DIRECTORY ${CMAKE_SOURCE_DIR}
)
