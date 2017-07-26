#include <iostream>
#include <string.h>
#include "encap_pcap.h"
#include "o_funcs.h"
using namespace std;

char* pcap_lookupdev_with_prompts(char* errBuf)
{
    char* deviceName;
    cout<<"Looking for suitable device...";
    deviceName = pcap_lookupdev(errBuf);
    if(deviceName)//success 
    {  
	cout<<"done.  device:"<<deviceName<<endl;
    }
    else          //fail
    {
	//TODO: errorCode.
	output_error_msg_and_exit(errBuf,0);
    }
    return deviceName;
}

pcap_if_t find_device_by_name(const char* deviceName)
{
    pcap_if_t *alldevs;/*point to the first element of the list*/
    char errbuf[PCAP_ERRBUF_SIZE];

    /*pcap_findalldevs() returns 0 on success and -1 on failure;               */
    /*finding no devices is considered success, rather than failure.           */
    /*if -1 is returned, errbuf is filled in with an appropriate error message.*/
    if (pcap_findalldevs(&alldevs,errbuf)==-1)
    {
	//TODO: output error msg and exit.
	fprintf(stderr, "Error in pcap_findalldevs: %s\n", errbuf);
	cout<<errbuf<<endl;
    }

    for(pcap_if_t* d=alldevs;d;d=d->next)
    {
	if(!strcmp(alldevs->name,deviceName))
	{
	    pcap_if_t device = *d;
	    return device;
	}
    }
}

bool if_device_has_address(const char* deviceName)
{
    pcap_if_t device = find_device_by_name(deviceName);
    if(device.addresses)
    {
	return true;
    }
    else
	return false;
}
