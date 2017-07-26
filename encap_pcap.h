#ifndef ENCAP_PCAP_H
#define ENCAP_PCAP_H

#include<pcap.h>

/* Encapsulate pcap_lookupdev. look for a suitable
   device for capture or injection with prompts. */
char* pcap_lookupdev_with_prompts(char* errBuf);

pcap_if_t find_device_by_name(const char* deviceName);

/* returns true on having and false on contrary. */
bool if_device_has_address(const char* deviceName);

#endif //ENCAP_PCAP_H
