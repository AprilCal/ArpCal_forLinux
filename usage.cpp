#include "usage.h"
#include <iostream>

void print_usage(){
    std::cout <<"ArpCal [--version][--help]<command>[args]\n\n"<<
		"These are common commands used in various situations:\n"<<
		"    attack    arp attack.\n"<<
		"    list      list interface information.\n"<<
		"    detect    detect if there are any arp spoofing attact or promiscuous host inside the LAN.\n\n"<<
		"use ArpCal <command> --help to see details.\n";
}

void print_attack_usage(){
    std::cout<< "ArpCal attack <target><spoofing ip><time>[timeUnit][intervalTime]\n\n"<<
		"target represent the target ip to attack.\n"<<
		"spoofing ip means the ip to fake.\n"<<
		"timeUnit={second|minute|hour}. The default time unit is second.\n"<<
		"The unit of intervalTime is milisecond, which is of 500 default value.\n"<<
		"    -h --help\n"<<
		"    -q --quiet            be quiet.\n"<<
		"    -v --verbose          be more stupid.\n"<<
		"    -f --force            break through firewall(if there is one).\n";
}
void print_list_usage(){
    std::cout<< "ArpCal list [<object>][flags]\n\n"<<
		"object={deviceName|devices}.\n"<<
		"    DeviceName represent a specific device on the local machine.\n"<<
		"    devices represent all apaper on the local machine.\n"<<
		"    -h --help            output help information.\n"<<
		"    -u --usb             usb interface.\n"<<
		"    -v --verbose         output more information.*/\n";
}
void print_detect_usage(){
    std::cout<< "ArpCal detect [promisc|attack][flags]\n\n"<<
		"    -h --help\n"<<
	  	"    -v --verbose         output more information.\n"<<
		"    -p --promiscuous      detect promiscuous host inside LAN.\n"<<
		"    -p --packet          output suspecious packet meanwhile.\n"<<
		"    -a --attack          detect attack in daemon process.}\n";
}
