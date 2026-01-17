#include "../../include/configuration/Config.h"
#include <boost/json/src.hpp>
#include <pcapplusplus/PcapLiveDeviceList.h>

void load(){

};
// TODO Fix later
std::vector<pcpp::PcapLiveDevice*> Config::getCaptureInterfaces()
{
    pcpp::PcapLiveDevice* captureInterface = pcpp::PcapLiveDeviceList::getInstance().getDeviceByName("ens34");
    std::vector<pcpp::PcapLiveDevice*> vector;
    vector.push_back(captureInterface);

    return vector;
};

void Config::parseDecryptionProfile(const boost::json::value& object)
{
    printf("parseDecryptionProfile\n");
};
void Config::parseSecurityPolicy(const boost::json::value& object)
{
    printf("parseSecurityPolicy\n");
};
void Config::parseNatPolicy(const boost::json::value& object)
{
    printf("parseNatPolicy\n");
};
void Config::parseRoutingTable(const boost::json::value& object)
{
    printf("parseRoutingTable\n");
};
void Config::loadFromFile(const std::string& filepath)
{
    printf("loadFromFile\n");
};
void Config::parseInterfaces(const boost::json::value& object)
{
    printf("parseInterfaces\n");
};
void Config::loadMalwareDatabase(const boost::json::value& object)
{
    printf("loadMalwareDatabase\n");
};

