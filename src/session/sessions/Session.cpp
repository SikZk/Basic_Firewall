#include "../../../include/session/sessions/Session.h"
#include <algorithm>
#include <cstring>

Session::Session(
    pcpp::IPv4Address firewall_interface_src_ip,
    pcpp::IPv4Address firewall_interface_dest_ip,
    pcpp::IPv4Address source_ip,
    uint16_t source_port,
    pcpp::IPv4Address destination_ip,
    uint16_t destination_port
)
    : source_to_destination{source_ip, source_port, destination_ip, destination_port},
      destination_to_source{destination_ip, destination_port, source_ip, source_port},
      session_state(HANDSHAKE_INIT),
      data(nullptr),
      data_length(0),
      data_capacity(0)
{
    (void)firewall_interface_src_ip;
    (void)firewall_interface_dest_ip;
}

SessionFlowKey Session::generateSessionFlowKey(
    pcpp::IPv4Address source_ip,
    uint16_t source_port,
    pcpp::IPv4Address destination_ip,
    uint16_t destination_port
){
    return SessionFlowKey{source_ip, source_port, destination_ip, destination_port, pcpp::TCP};
}
uint8_t* Session::getData()
{
    return this->data;
};
size_t Session::getDataLength()
{
    return this->data_length;
};
void Session::appendData(const uint8_t* new_data, size_t length)
{
    if (new_data == nullptr || length == 0)
        return;

    size_t required = data_length + length;
    if (required > data_capacity)
    {
        size_t new_capacity = std::max(required, data_capacity == 0 ? size_t{256} : data_capacity * 2);

        uint8_t* new_buf = new uint8_t[new_capacity];

        if (data != nullptr && data_length > 0)
            std::memcpy(new_buf, data, data_length);

        delete[] data;

        data = new_buf;
        data_capacity = new_capacity;
    }

    std::memcpy(data + data_length, new_data, length);
    data_length += length;
};

const SessionFlow& Session::getSourceToDestinationFlow() const
{
    return source_to_destination;
}

const SessionFlow& Session::getDestinationToSourceFlow() const
{
    return destination_to_source;
}
