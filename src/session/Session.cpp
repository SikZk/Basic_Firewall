#include "../../include/session/sessions/Session.h"

Session::Session(
    pcpp::IPv4Address firewall_interface_src_ip,
    pcpp::IPv4Address firewall_interface_dest_ip,
    pcpp::IPv4Address source_ip,
    uint16_t          source_port,
    pcpp::IPv4Address destination_ip,
    uint16_t          destination_port
) {
    source_to_destination = {source_ip, source_port, destination_ip, destination_port};
    destination_to_source = {destination_ip, destination_port, source_ip, source_port};
    session_state = ESTABLISHED;
    (void)firewall_interface_src_ip;
    (void)firewall_interface_dest_ip;
}

SessionFlowKey Session::generateSessionFlowKey(
    pcpp::IPv4Address source_ip,
    uint16_t          source_port,
    pcpp::IPv4Address destination_ip,
    uint16_t          destination_port
) {
    return {source_ip, source_port, destination_ip, destination_port, pcpp::TCP};
}

uint8_t* Session::getData() {
    return data_buffer.empty() ? nullptr : data_buffer.data();
}

const uint8_t* Session::getData() const {
    return data_buffer.empty() ? nullptr : data_buffer.data();
}

uint8_t Session::getDataLength() const {
    return static_cast<uint8_t>(data_buffer.size());
}

uint8_t Session::appendData(uint8_t* new_data, uint8_t length) {
    data_buffer.insert(data_buffer.end(), new_data, new_data + length);
    return static_cast<uint8_t>(data_buffer.size());
}
