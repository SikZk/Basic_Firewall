#include "../../../include/session/sessions/Session.h"

static SessionFlowKey generateSessionFlowKey(
    pcpp::IPv4Address source_ip,
    uint16_t          source_port,
    pcpp::IPv4Address destination_ip,
    uint16_t          destination_port
){

};
uint8_t* Session::getData()
{
    return this->data;
};
uint8_t Session::getDataLength()
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