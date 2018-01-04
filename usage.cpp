#include "usage.h"
#include <iostream>

void print_usage(){
	std::cout<<"ArpCal [--version][--help]<command>[args]\n\n"<<
	      "These are common commands used in various situations:\n"<<
	      "    attack    arp attack.\n"<<
	      "    list      list interface information.\n"<<
	      "    detect    detect if there are any arp spoofing attact or promiscuous host inside the LAN.\n\n"<<
	      "use ArpCal <command> --help to see details.\n";
}
